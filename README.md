# Wazuh Troubleshooter AI Workflow

A Telegram chatbot that diagnoses Wazuh SIEM/XDR issues through natural language using an LLM (GLM-4.5-Air via Ollama) and LangGraph tool orchestration. Send a question from your phone; the bot SSHes into your Wazuh managers, runs read-only diagnostics, and replies with a human-readable analysis.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [How It Works](#how-it-works)
3. [Prerequisites](#prerequisites)
4. [Deployment Topology](#deployment-topology)
5. [Step 1 — Create a Telegram Bot](#step-1--create-a-telegram-bot)
6. [Step 2 — Find Your Telegram User ID](#step-2--find-your-telegram-user-id)
7. [Step 3 — Install Ollama and Pull the LLM](#step-3--install-ollama-and-pull-the-llm)
8. [Step 4 — Prepare the Bot Host](#step-4--prepare-the-bot-host)
9. [Step 5 — Generate an SSH Key Pair](#step-5--generate-an-ssh-key-pair)
10. [Step 6 — Create the `wazuh-advisor` User on Each Wazuh Manager](#step-6--create-the-wazuh-advisor-user-on-each-wazuh-manager)
11. [Step 7 — Authorize the SSH Key on Each Wazuh Manager](#step-7--authorize-the-ssh-key-on-each-wazuh-manager)
12. [Step 8 — Add Each Host to `known_hosts`](#step-8--add-each-host-to-known_hosts)
13. [Step 9 — Configure `hosts.yaml`](#step-9--configure-hostsyaml)
14. [Step 10 — Configure `.env`](#step-10--configure-env)
15. [Step 11 — Install Python Dependencies](#step-11--install-python-dependencies)
16. [Step 12 — Run the Bot](#step-12--run-the-bot)
17. [Step 13 — Run as a systemd Service (Production)](#step-13--run-as-a-systemd-service-production)
18. [Verifying the Setup](#verifying-the-setup)
19. [Usage Examples](#usage-examples)
20. [Diagnostic Tools Reference](#diagnostic-tools-reference)
21. [Adding More Hosts](#adding-more-hosts)
22. [File Reference](#file-reference)
23. [Security Notes](#security-notes)
24. [Troubleshooting the Bot Itself](#troubleshooting-the-bot-itself)

---

## Architecture Overview

```
You (Telegram)
      │
      ▼
Telegram Bot API
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  Bot Host  (Linux server running this repo)         │
│                                                     │
│  advisor.py  ──────  LangGraph Workflow             │
│      │                    │                         │
│      │         ┌──────────┴────────────┐            │
│      │         │  LLM Agent  (Ollama)  │            │
│      │         │  GLM-4.5-Air          │            │
│      │         └──────────┬────────────┘            │
│      │                    │ tool calls               │
│      │         ┌──────────┴────────────┐            │
│      │         │  tools.py             │            │
│      │         │  6 diagnostic tools   │            │
│      │         └──────────┬────────────┘            │
│      │                    │ SSH                      │
│  ssh_client.py            │                         │
│  (Paramiko pool) ─────────┘                         │
│                                                     │
│  advisor.db  (SQLite — conversation memory)         │
│  hosts.yaml  (fleet registry)                       │
└────────────────────┬────────────────────────────────┘
                     │ SSH (port 22)
          ┌──────────┴──────────────────────┐
          │                                 │
    ┌─────┴─────┐                   ┌───────┴───────┐
    │ Wazuh Mgr │                   │ Wazuh Mgr     │
    │ client-a  │     . . .         │ client-b      │
    └───────────┘                   └───────────────┘
```

**Key design decisions:**

- The bot host can be any Linux machine with network access to your Wazuh managers — it does **not** need to be one of the Wazuh managers itself.
- The LLM runs locally via Ollama. No data leaves your network (except through Telegram for the user-facing messages).
- All SSH commands are read-only. The bot can inspect but never modify Wazuh.
- Conversation history is stored in a local SQLite database (`advisor.db`) so multi-turn troubleshooting sessions work across restarts.

---

## How It Works

1. You send a message to your Telegram bot (e.g., "Check if all daemons are running on client-a").
2. `advisor.py` validates that the message is from your authorized user ID.
3. The message is fed into a **LangGraph** stateful graph as a `HumanMessage`.
4. The **LLM agent node** reads your system prompt (from `skills.md`, including the list of available hosts) and decides which diagnostic tools to call.
5. The **tools node** executes the chosen tool — opening an SSH connection via Paramiko, running a specific read-only command (e.g., `ps aux`, `ss -tlnp`, `curl _cluster/health`), and returning the output.
6. The result is fed back to the LLM, which may call more tools or synthesize a final response.
7. The final response is sent back to you on Telegram (truncated to 4096 characters if needed).
8. The entire exchange is checkpointed to `advisor.db` under a key matching your Telegram chat ID.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11+ | On the bot host |
| [Ollama](https://ollama.com/) | Installed on the bot host |
| Telegram account | To create the bot and receive messages |
| Wazuh manager(s) | Must be SSH-accessible from the bot host |
| Linux bot host | `systemd` assumed for the service section |

---

## Deployment Topology

**Minimal (single machine):** Run the bot on the Wazuh manager itself. Ollama runs locally. SSH connections go to `127.0.0.1` or `localhost`.

**Recommended (dedicated bot host):** A separate lightweight VM runs the bot and Ollama. It reaches all Wazuh managers over your internal network via SSH. This isolates the bot process from your Wazuh infrastructure.

**Multi-manager:** Add one block per manager to `hosts.yaml`. The bot maintains a persistent SSH connection pool and can interrogate any host in a single conversation.

---

## Step 1 — Create a Telegram Bot

1. Open Telegram and search for **@BotFather**.
2. Send `/newbot`.
3. Follow the prompts: choose a display name (e.g., `Wazuh Advisor`) and a username ending in `bot` (e.g., `wazuh_advisor_bot`).
4. BotFather will reply with a **bot token** that looks like:
   ```
   1234567890:ABCDefGhIJKlmNoPQRsTUVwxyZ
   ```
5. Copy and save this token — you will put it in `.env` as `TELEGRAM_BOT_TOKEN`.

> **Security:** Anyone with this token can send messages as your bot. Treat it like a password and never commit it to version control.

---

## Step 2 — Find Your Telegram User ID

The bot uses a strict user ID whitelist — only the numeric ID in `TELEGRAM_USER_ID` can interact with it.

1. Open Telegram and search for **@userinfobot**.
2. Send `/start`.
3. It will reply with your numeric user ID (e.g., `987654321`).
4. Save this — you will put it in `.env` as `TELEGRAM_USER_ID`.

---

## Step 3 — Install Ollama and Pull the LLM

On the **bot host**:

### Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verify it is running:

```bash
systemctl status ollama
# or manually: ollama serve &
```

Check the API is reachable:

```bash
curl http://localhost:11434/api/tags
```

### Pull the model

```bash
ollama pull MichelRosselli/GLM-4.5-Air
```

This model is approximately 9 GB. The pull may take several minutes depending on your connection. Once complete, verify:

```bash
ollama list
# Should show: MichelRosselli/GLM-4.5-Air
```

> **Alternative model:** You can use any model available in Ollama by setting `OLLAMA_MODEL` in `.env`. The system prompt and tool descriptions are optimized for instruction-following models. GLM-4.5-Air is used by default.

---

## Step 4 — Prepare the Bot Host

### Clone or copy the project files

```bash
sudo mkdir -p /opt/wazuh-advisor
sudo chown $USER:$USER /opt/wazuh-advisor
cp -r /path/to/this/repo/* /opt/wazuh-advisor/
cd /opt/wazuh-advisor
```

Confirm the directory structure:

```
/opt/wazuh-advisor/
├── advisor.py
├── tools.py
├── ssh_client.py
├── skills.md
├── hosts.yaml
├── .env.example
├── requirements.txt
├── ssh-key/
│   ├── wazuh_advisor.ppk
│   └── wazuh_advisor.pub
└── wazuh_skills/
    ├── SKILL.md
    └── references/
        ├── agent-troubleshooting.md
        ├── cert-renewal.md
        ├── fim-sca.md
        ├── indexer-ops.md
        ├── log-ingestion.md
        └── log-locations.md
```

---

## Step 5 — Generate an SSH Key Pair

The bot authenticates to each Wazuh manager using a dedicated SSH key. **Never reuse your personal SSH key.**

### Option A — Generate on Linux (OpenSSH format, recommended)

```bash
ssh-keygen -t ed25519 -C "wazuh-advisor-bot" -f /opt/wazuh-advisor/ssh-key/wazuh_advisor
```

This creates:
- `/opt/wazuh-advisor/ssh-key/wazuh_advisor` — private key
- `/opt/wazuh-advisor/ssh-key/wazuh_advisor.pub` — public key

Set permissions:

```bash
chmod 600 /opt/wazuh-advisor/ssh-key/wazuh_advisor
chmod 644 /opt/wazuh-advisor/ssh-key/wazuh_advisor.pub
```

The bot enforces `chmod 600` (or stricter) on startup and **will refuse to start** if the key is group- or world-readable.

### Option B — Convert an existing PuTTY key (.ppk)

If you already have a `.ppk` file (PuTTY format), Paramiko can read PuTTY keys directly. Place the `.ppk` file at `ssh-key/wazuh_advisor.ppk` and update `ssh_key` in `hosts.yaml` accordingly. Ensure the file has `chmod 600`.

### Update `hosts.yaml`

In `hosts.yaml`, set `ssh_key` to the **absolute path** of the private key on the bot host:

```yaml
ssh_key: /opt/wazuh-advisor/ssh-key/wazuh_advisor
```

---

## Step 6 — Create the `wazuh-advisor` User on Each Wazuh Manager

On **each Wazuh manager**, create a low-privilege dedicated user for the bot:

```bash
# Create user (no login shell, no password)
sudo useradd -r -s /bin/bash -m wazuh-advisor

# Create the .ssh directory
sudo mkdir -p /home/wazuh-advisor/.ssh
sudo chmod 700 /home/wazuh-advisor/.ssh
sudo chown wazuh-advisor:wazuh-advisor /home/wazuh-advisor/.ssh
```

### Grant sudo access for diagnostic commands only

Create a sudoers file that allows the user to run exactly the commands the bot needs:

```bash
sudo visudo -f /etc/sudoers.d/wazuh-advisor
```

Add the following (adjust paths if your Wazuh install differs):

```
# Allow wazuh-advisor bot to run read-only diagnostics
wazuh-advisor ALL=(ALL) NOPASSWD: /usr/bin/ss -tlnp
wazuh-advisor ALL=(ALL) NOPASSWD: /usr/bin/grep -E * /var/ossec/logs/ossec.log
wazuh-advisor ALL=(ALL) NOPASSWD: /usr/bin/grep -E * /var/ossec/logs/api.log
wazuh-advisor ALL=(ALL) NOPASSWD: /usr/bin/df -i
wazuh-advisor ALL=(ALL) NOPASSWD: /var/ossec/bin/wazuh-analysisd -t
```

> **Why sudo?** Some commands (`ss -tlnp`, reading `/var/ossec/logs/`) require elevated privileges. The sudoers rules above scope the permission narrowly to the exact executables the bot calls.

---

## Step 7 — Authorize the SSH Key on Each Wazuh Manager

Copy the **public key** from the bot host to each Wazuh manager.

### From the bot host (easiest):

```bash
ssh-copy-id -i /opt/wazuh-advisor/ssh-key/wazuh_advisor.pub \
    wazuh-advisor@<WAZUH_MANAGER_IP>
```

### Manually (if ssh-copy-id is not available):

1. Print the public key on the bot host:

   ```bash
   cat /opt/wazuh-advisor/ssh-key/wazuh_advisor.pub
   ```

2. On the Wazuh manager, as root or the `wazuh-advisor` user:

   ```bash
   sudo -u wazuh-advisor bash
   echo "ssh-ed25519 AAAA...your-key-here... wazuh-advisor-bot" \
       >> /home/wazuh-advisor/.ssh/authorized_keys
   chmod 600 /home/wazuh-advisor/.ssh/authorized_keys
   chown wazuh-advisor:wazuh-advisor /home/wazuh-advisor/.ssh/authorized_keys
   ```

### Test the connection from the bot host:

```bash
ssh -i /opt/wazuh-advisor/ssh-key/wazuh_advisor \
    -p 22 \
    wazuh-advisor@<WAZUH_MANAGER_IP> \
    "echo SSH OK"
```

You should see `SSH OK` with no password prompt. If prompted, the key is not correctly authorized — re-check Step 7.

---

## Step 8 — Add Each Host to `known_hosts`

The bot uses `RejectPolicy` — it will **refuse to connect** to any host not already in `~/.ssh/known_hosts`. This prevents man-in-the-middle attacks at the cost of a one-time manual step.

Run this **once per Wazuh manager**, from the bot host, as the user that will run the bot:

```bash
ssh-keyscan -H <WAZUH_MANAGER_IP> >> ~/.ssh/known_hosts
# If using a non-standard SSH port:
ssh-keyscan -H -p <PORT> <WAZUH_MANAGER_IP> >> ~/.ssh/known_hosts
```

Verify the entry was added:

```bash
ssh-keygen -F <WAZUH_MANAGER_IP>
# Should print the host's key fingerprint
```

> If you skip this step, the bot will log an error like `No hostkey for host X is found in known_hosts` and fail to connect.

---

## Step 9 — Configure `hosts.yaml`

`hosts.yaml` is the fleet registry. It lists every Wazuh manager the bot can reach. **This file contains no secrets** — passwords are referenced by environment variable name, not stored here.

Open `/opt/wazuh-advisor/hosts.yaml`:

```yaml
hosts:
  - name: client-a                          # Friendly name used in chat and tool calls
    hostname: 192.168.13.134                # IP or FQDN of the Wazuh manager
    ssh_port: 22
    ssh_user: wazuh-advisor                 # The user you created in Step 6
    ssh_key: /opt/wazuh-advisor/ssh-key/wazuh_advisor   # Absolute path to private key
    indexer_host: https://192.168.13.134:9200  # OpenSearch/Wazuh Indexer URL (from the manager's perspective)
    indexer_user: admin
    indexer_password_env: INDEXER_PASS_CLIENT_A   # Name of env var holding the indexer password
    tags: [production, my-client]
```

### Field reference

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Identifier used in chat. Use lowercase with hyphens. |
| `hostname` | Yes | IP address or fully-qualified domain name of the Wazuh manager. |
| `ssh_port` | Yes | SSH port (usually `22`). |
| `ssh_user` | Yes | The dedicated user created in Step 6. |
| `ssh_key` | Yes | Absolute path to the **private** key file on the bot host. |
| `indexer_host` | Yes | URL of the Wazuh Indexer (OpenSearch). Use `https://localhost:9200` if the indexer is on the same host as the manager. |
| `indexer_user` | Yes | OpenSearch admin username (usually `admin`). |
| `indexer_password_env` | Yes | Name of the environment variable in `.env` that holds the indexer password for this host. |
| `tags` | No | Arbitrary labels. Not used by the bot logic currently. |

> **`indexer_host`**: The `check_indexer_health` tool curls this URL **from the bot host**, not from the Wazuh manager. If the indexer is not reachable from the bot host, use an SSH tunnel or expose the port to the bot host's network. Alternatively, if the indexer runs on the same host as the manager, the command is run over SSH and `localhost` is correct from the manager's perspective.

---

## Step 10 — Configure `.env`

```bash
cp /opt/wazuh-advisor/.env.example /opt/wazuh-advisor/.env
chmod 600 /opt/wazuh-advisor/.env
nano /opt/wazuh-advisor/.env
```

### Required variables

```ini
TELEGRAM_BOT_TOKEN=1234567890:ABCDefGhIJKlmNoPQRsTUVwxyZ
TELEGRAM_USER_ID=987654321
```

### Per-host indexer passwords

For each host in `hosts.yaml`, add a matching password variable. The variable name must exactly match the `indexer_password_env` field:

```ini
INDEXER_PASS_CLIENT_A=your-indexer-admin-password
INDEXER_PASS_CLIENT_B=another-password
```

> The bot will **crash at startup** with a clear error message if any `indexer_password_env` variable is missing from `.env`. This is intentional (fail-fast security).

### Optional variables

```ini
# Which Ollama model to use (default: MichelRosselli/GLM-4.5-Air)
OLLAMA_MODEL=MichelRosselli/GLM-4.5-Air

# Where Ollama is listening (default: http://localhost:11434)
OLLAMA_HOST=http://localhost:11434

# Timeout per diagnostic tool in seconds (default: 15)
TOOL_TIMEOUT_SECONDS=15
```

### Full example `.env`

```ini
TELEGRAM_BOT_TOKEN=1234567890:ABCDefGhIJKlmNoPQRsTUVwxyZ
TELEGRAM_USER_ID=987654321

OLLAMA_MODEL=MichelRosselli/GLM-4.5-Air
OLLAMA_HOST=http://localhost:11434
TOOL_TIMEOUT_SECONDS=15

INDEXER_PASS_CLIENT_A=MySecurePassword!
```

---

## Step 11 — Install Python Dependencies

On the bot host:

```bash
cd /opt/wazuh-advisor
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

This installs:

| Package | Purpose |
|---|---|
| `python-telegram-bot==22.6` | Telegram Bot API client |
| `langchain==1.2.12` | LLM framework |
| `langchain-ollama==1.0.1` | LangChain ↔ Ollama integration |
| `langchain-core==1.2.19` | LangChain core types |
| `langgraph==1.1.2` | Stateful agent graph orchestration |
| `langgraph-checkpoint-sqlite==3.0.3` | SQLite backend for conversation memory |
| `python-dotenv==1.2.1` | `.env` file loading |
| `paramiko==4.0.0` | SSH client |
| `pyyaml>=6.0` | YAML parsing |

---

## Step 12 — Run the Bot

```bash
cd /opt/wazuh-advisor
source .venv/bin/activate
python advisor.py
```

### What happens at startup

1. `.env` is loaded.
2. `hosts.yaml` is parsed and all `indexer_password_env` variables are resolved — the bot exits immediately if any are missing.
3. `skills.md` is loaded as the LLM system prompt. The list of available hosts is appended dynamically.
4. SSH key permissions are checked — the bot exits if any key is group- or world-readable.
5. Ollama connectivity is verified — the bot exits if Ollama is unreachable.
6. The LangGraph workflow is compiled with a SQLite checkpointer (`advisor.db`).
7. The Telegram polling loop starts.

### Expected startup output

```
INFO  advisor: Fleet loaded: ['client-a']
INFO  advisor: Ollama reachable at http://localhost:11434
INFO  advisor: Bot started. Listening for messages...
```

### Stopping the bot

Press `Ctrl+C`. The bot will close all SSH connections gracefully.

---

## Step 13 — Run as a systemd Service (Production)

Create the unit file:

```bash
sudo nano /etc/systemd/system/wazuh-advisor.service
```

Paste:

```ini
[Unit]
Description=Wazuh Troubleshooter AI Advisor
After=network.target ollama.service

[Service]
Type=simple
User=wazuh-advisor
WorkingDirectory=/opt/wazuh-advisor
EnvironmentFile=/opt/wazuh-advisor/.env
ExecStart=/opt/wazuh-advisor/.venv/bin/python advisor.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

> **`User=wazuh-advisor`**: The service runs as the same OS user that owns the SSH keys and `known_hosts` entries. If you created the `wazuh-advisor` user in Step 6 only on the remote managers, create a separate local service account on the bot host and ensure it owns `/opt/wazuh-advisor` and `~/.ssh/known_hosts`.

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-advisor
```

Check status:

```bash
sudo systemctl status wazuh-advisor
```

Follow logs in real time:

```bash
sudo journalctl -u wazuh-advisor -f
```

### Permissions checklist for the service user

```bash
# Ownership of the project directory
sudo chown -R wazuh-advisor:wazuh-advisor /opt/wazuh-advisor

# SSH key permissions
sudo chmod 600 /opt/wazuh-advisor/ssh-key/wazuh_advisor
sudo chmod 644 /opt/wazuh-advisor/ssh-key/wazuh_advisor.pub

# .env must not be world-readable
sudo chmod 600 /opt/wazuh-advisor/.env

# known_hosts (run as the service user)
sudo -u wazuh-advisor ssh-keyscan -H <WAZUH_MANAGER_IP> >> /home/wazuh-advisor/.ssh/known_hosts
```

---

## Verifying the Setup

### 1. Confirm Ollama is responding

```bash
curl http://localhost:11434/api/tags | python3 -m json.tool
# Look for MichelRosselli/GLM-4.5-Air in the response
```

### 2. Confirm SSH access

```bash
# As the bot service user:
sudo -u wazuh-advisor ssh \
    -i /opt/wazuh-advisor/ssh-key/wazuh_advisor \
    wazuh-advisor@<WAZUH_MANAGER_IP> \
    "ps aux | grep wazuh"
```

### 3. Send a test message on Telegram

Send your bot: `ping`

The bot should respond within a few seconds (LLM inference + SSH round-trip). If it doesn't respond after 30 seconds, check `advisor.log`.

### 4. Check the log file

```bash
tail -f /opt/wazuh-advisor/advisor.log
```

---

## Usage Examples

Ask the bot any natural-language question. Always specify the host by name (as defined in `hosts.yaml`), or the bot will ask you to clarify.

```
Are all Wazuh daemons running on client-a?
Check the indexer health on client-a
Why are agents disconnecting from client-a?
Are there any CRITICAL errors in the logs on client-a?
Validate the Wazuh config on client-a
Check disk space and ulimits on client-a
Is the API port listening on client-a?
Search for "authentication failure" errors on client-a
Run a full health check on client-a
```

The bot maintains conversation context — you can follow up without repeating the host name:

```
You: Check indexer health on client-a
Bot: [reports yellow status with unassigned shards]
You: What could cause unassigned shards?
Bot: [explains common causes based on the output it already retrieved]
```

---

## Diagnostic Tools Reference

The bot has six read-only diagnostic tools. The LLM selects which ones to call based on your question.

| Tool | What it runs | What it tells you |
|---|---|---|
| `audit_os_resources` | `df -i`, `ulimit -a` | Disk inode exhaustion, JVM heap, file descriptor limits |
| `validate_wazuh_config` | `xmllint /var/ossec/etc/ossec.conf`, `wazuh-analysisd -t` | XML syntax errors, internal config consistency |
| `check_wazuh_daemons` | `ps aux` | Running/stopped status of analysisd, remoted, authd, db, modulesd |
| `audit_wazuh_networking` | `ss -tlnp` | Whether ports 1514, 1515, 1516, 9200, 55000 are listening |
| `check_indexer_health` | `curl <indexer>/_cluster/health?pretty` | OpenSearch cluster status, shard counts, unassigned shards |
| `search_wazuh_errors` | `grep -E <pattern> /var/ossec/logs/ossec.log` and `api.log` | Last 15 matches of ERROR/CRITICAL (or a custom pattern) |

---

## Adding More Hosts

1. **Create the `wazuh-advisor` user** on the new manager (Step 6).
2. **Authorize the SSH key** on the new manager (Step 7).
3. **Add the host to `known_hosts`** from the bot host (Step 8).
4. **Add a block to `hosts.yaml`**:

   ```yaml
   - name: client-b
     hostname: 10.0.0.5
     ssh_port: 22
     ssh_user: wazuh-advisor
     ssh_key: /opt/wazuh-advisor/ssh-key/wazuh_advisor
     indexer_host: https://localhost:9200
     indexer_user: admin
     indexer_password_env: INDEXER_PASS_CLIENT_B
     tags: [staging]
   ```

5. **Add the password to `.env`**:

   ```ini
   INDEXER_PASS_CLIENT_B=another-password
   ```

6. **Restart the bot**:

   ```bash
   sudo systemctl restart wazuh-advisor
   ```

The new host is immediately available in the next conversation.

---

## File Reference

```
advisor.py                   Main application — Telegram bot + LangGraph graph
tools.py                     Six diagnostic tool definitions (@tool decorated functions)
ssh_client.py                Paramiko-based persistent SSH connection pool
skills.md                    LLM system prompt and advisor persona
hosts.yaml                   Fleet registry — one block per Wazuh manager
.env.example                 Template for environment variables
.env                         Your secrets (never commit this)
requirements.txt             Python package dependencies
advisor.db                   SQLite conversation memory (auto-created on first run)
advisor.log                  Runtime log (auto-created on first run)
ssh-key/wazuh_advisor.ppk    Private SSH key (PuTTY format, if using PPK)
ssh-key/wazuh_advisor.pub    Public SSH key
wazuh_skills/SKILL.md        Master Wazuh troubleshooting knowledge base (363 lines)
wazuh_skills/references/     Deep-dive reference documents:
  agent-troubleshooting.md     Linux, Windows, Kubernetes agent debug guide
  cert-renewal.md              Certificate expiry, regeneration, and installation
  fim-sca.md                   File Integrity Monitoring and SCA policy guide
  indexer-ops.md               OpenSearch index management, ILM, snapshots, tuning
  log-ingestion.md             Syslog, CEF, JSON, Filebeat, custom decoders
  log-locations.md             All Wazuh log paths and verbosity tuning
```

---

## Security Notes

- **Single-user whitelist.** Only the Telegram user ID in `TELEGRAM_USER_ID` can interact with the bot. Messages from any other user are silently dropped.
- **Never commit `.env`.** It contains your Telegram bot token and indexer passwords. Add it to `.gitignore`.
- **SSH key permissions enforced at startup.** If `ssh_key` is group- or world-readable (not `chmod 600`), the bot refuses to start.
- **No host key auto-acceptance.** The SSH client uses `RejectPolicy` — it will only connect to hosts already in `~/.ssh/known_hosts`. Run `ssh-keyscan` for each host before starting (Step 8).
- **Command injection prevention.** Every command token is validated against a forbidden-character list and quoted with `shlex.quote()` before execution. Shell metacharacters (`;`, `&`, `|`, `$`, backticks) cause the command to be rejected and an error returned to the LLM.
- **Read-only by design.** All tools are diagnostic. The bot cannot restart services, modify configuration files, enroll agents, or trigger active responses.
- **Indexer password isolation.** Passwords are stored in `.env` and referenced by variable name in `hosts.yaml`. `hosts.yaml` is safe to commit.
- **Minimal sudo scope.** The `wazuh-advisor` user on each manager should be granted only the specific `sudo NOPASSWD` rules it needs, not blanket `ALL=(ALL) NOPASSWD: ALL`.

---

## Troubleshooting the Bot Itself

### Bot doesn't respond on Telegram

1. Check that the bot is running: `systemctl status wazuh-advisor`
2. Check the log: `tail -100 /opt/wazuh-advisor/advisor.log`
3. Confirm your `TELEGRAM_USER_ID` matches the account you're messaging from. Message `@userinfobot` to confirm your ID.
4. Confirm the bot token is valid by running: `curl "https://api.telegram.org/bot<TOKEN>/getMe"`

### "SSH connection refused" or "No hostkey found"

- Verify `known_hosts` has an entry: `ssh-keygen -F <WAZUH_MANAGER_IP>`
- Test SSH manually as the service user (see [Verifying the Setup](#verifying-the-setup))
- Confirm the `wazuh-advisor` user exists on the manager: `id wazuh-advisor`
- Confirm the public key is in `/home/wazuh-advisor/.ssh/authorized_keys` on the manager

### "Permission denied" for SSH key at startup

```
PermissionError: SSH key /opt/wazuh-advisor/ssh-key/wazuh_advisor has unsafe permissions
```

Fix:

```bash
chmod 600 /opt/wazuh-advisor/ssh-key/wazuh_advisor
```

### "Missing environment variable" at startup

```
KeyError: 'INDEXER_PASS_CLIENT_A'
```

Add the missing variable to `.env` and restart.

### Ollama not reachable

```
ConnectionRefusedError: [Errno 111] Connection refused
```

- Check Ollama is running: `systemctl status ollama`
- Confirm the model is pulled: `ollama list`
- If Ollama is on a different host, update `OLLAMA_HOST` in `.env`

### Tool calls time out

If commands take longer than `TOOL_TIMEOUT_SECONDS` (default 15 s), the tool returns a timeout error to the LLM. Increase the value in `.env`:

```ini
TOOL_TIMEOUT_SECONDS=30
```

The entire graph execution has a hard 120-second timeout to prevent hung requests.

### Response truncated

Telegram messages are limited to 4096 characters. If the bot's response is longer, it is cut off. Ask for a more targeted query (e.g., "just show me the daemon status" instead of "run a full health check") or ask follow-up questions.
