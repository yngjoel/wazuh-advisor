---
name: wazuh_skills
description: >
  Deep technical troubleshooting for Wazuh SIEM/XDR deployments. Use this skill whenever the user mentions Wazuh, wazuh-manager, wazuh-indexer, wazuh-dashboard, ossec, wazuh-agent, or any related component. Trigger on: agent connectivity issues, rule/decoder problems, indexer errors, API failures, cluster split-brain, high CPU/memory on Wazuh processes, missing alerts, FIM issues, SCA failures, log ingestion problems, certificate errors, or any mention of wazuh logs, wazuh config files, or wazuh CLI tools. Also trigger for questions phrased as "why isn't Wazuh...", "Wazuh keeps...", "my agents aren't...", or any troubleshooting adjacent to security monitoring infrastructure.
---

# Wazuh Deep Troubleshooter

Expert-level troubleshooting guide for Wazuh 4.x deployments. Covers single-node and multi-node cluster topologies across Linux agents, Windows agents, and containerized environments.

---

## Troubleshooting Philosophy

1. **Establish baseline first** — version, topology, OS, recent changes
2. **Read logs at source** — don't guess; pull the actual error
3. **Isolate the layer** — agent → manager → indexer → dashboard; each has distinct failure modes
4. **Diff against known-good** — config drift is the #1 cause of silent failures
5. **Check resource ceilings** — Wazuh is unusually sensitive to ulimits, JVM heap, and inode exhaustion

---

## Quick Diagnostic Runbook

### Step 1 — Establish Context

Always ask or confirm:
```
Wazuh version:         wazuh-manager --version
OS / distro:           cat /etc/os-release
Topology:              single-node or multi-node cluster?
Recent changes:        package upgrades, config edits, cert renewals?
Symptom onset:         sudden vs gradual
```

### Step 2 — Service Health

```bash
# All-in-one status check
systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat

# Process-level
ps aux | grep -E 'wazuh|ossec|filebeat'

# Ports
ss -tlnp | grep -E '1514|1515|1516|9200|9300|443|55000'
```

Expected open ports:
| Port  | Service            | Protocol |
|-------|--------------------|----------|
| 1514  | Agent comms        | TCP/UDP  |
| 1515  | Agent enrollment   | TCP      |
| 1516  | Cluster comms      | TCP      |
| 9200  | Indexer REST API   | TCP      |
| 9300  | Indexer cluster    | TCP      |
| 55000 | Manager REST API   | TCP      |
| 443   | Dashboard          | TCP      |

### Step 3 — Log Triage

See `references/log-locations.md` for all log paths and what each file reveals.

---

## Subsystem Guides

### Manager

**Primary config:** `/var/ossec/etc/ossec.conf`  
**Validate config:**
```bash
/var/ossec/bin/wazuh-logtest          # test rules interactively
/var/ossec/bin/ossec-logtest -t       # validate ossec.conf syntax (legacy)
xmllint --noout /var/ossec/etc/ossec.conf   # XML validation
```

**Common manager failures:**

| Symptom | First check |
|---------|-------------|
| Manager won't start | `journalctl -u wazuh-manager -n 100` + `/var/ossec/logs/ossec.log` |
| No alerts generated | Check `alerts.log`, run `wazuh-logtest` against a sample event |
| High CPU on `wazuh-analysisd` | Rule complexity — check recursive rules, `<if_matched_sid>` chains |
| `ossec.conf` changes not applying | Config reload: `systemctl reload wazuh-manager` or `kill -HUP $(pidof wazuh-analysisd)` |
| Agents show "never connected" | Check `client.keys` — agent must be enrolled and key must match |

**Internal daemons and their roles:**
```
wazuh-analysisd   — rule evaluation engine
wazuh-remoted     — agent communication (port 1514)
wazuh-authd       — agent auto-enrollment (port 1515)
wazuh-db          — SQLite-backed event/state DB
wazuh-execd       — active response execution
wazuh-monitord    — log rotation and monitoring
wazuh-syscheckd   — FIM engine
wazuh-logcollector— local log ingestion
```

To check which daemon is erroring:
```bash
grep -E 'ERROR|CRITICAL|wazuh-' /var/ossec/logs/ossec.log | tail -50
```

---

### Indexer (OpenSearch-based)

**Config:** `/etc/wazuh-indexer/opensearch.yml`  
**JVM:** `/etc/wazuh-indexer/jvm.options`

**Health check:**
```bash
curl -sk -u admin:admin https://localhost:9200/_cluster/health?pretty
curl -sk -u admin:admin https://localhost:9200/_cluster/stats?pretty | jq '.indices'
curl -sk -u admin:admin https://localhost:9200/_cat/nodes?v
curl -sk -u admin:admin https://localhost:9200/_cat/shards?v | grep UNASSIGNED
```

**Common indexer failures:**

| Symptom | Diagnosis | Fix |
|---------|-----------|-----|
| `yellow` cluster status | Unassigned replica shards | Single-node: set `number_of_replicas: 0` on affected indices |
| `red` cluster status | Primary shard unassigned | Check `/_cluster/allocation/explain?pretty` |
| Indexer won't start | OOM or cert error | Check `/var/log/wazuh-indexer/wazuh-indexer.log` |
| High heap usage | JVM heap too low | Edit `jvm.options`: set `-Xms` and `-Xmx` to 50% of RAM, max 32g |
| Disk watermark hit | Disk >85% full | `curl .../disk.watermark.low` — indexer stops writing at 90% |
| Index rollover not happening | ILM policy misconfigured | Check `/_ilm/policy/wazuh-alerts` |

**Fix unassigned shards (single-node):**
```bash
curl -sk -XPUT -u admin:admin https://localhost:9200/_settings \
  -H 'Content-Type: application/json' \
  -d '{"index":{"number_of_replicas":"0"}}'
```

**Disk watermark override (emergency):**
```bash
curl -sk -XPUT -u admin:admin https://localhost:9200/_cluster/settings \
  -H 'Content-Type: application/json' \
  -d '{"transient":{"cluster.routing.allocation.disk.watermark.low":"95%","cluster.routing.allocation.disk.watermark.high":"97%","cluster.routing.allocation.disk.watermark.flood_stage":"99%"}}'
```

---

### Dashboard

**Config:** `/etc/wazuh-dashboard/opensearch_dashboards.yml`  
**Logs:** `journalctl -u wazuh-dashboard -f`

**Common dashboard failures:**

| Symptom | Check |
|---------|-------|
| "Server not ready" | Indexer unreachable — check certs and `opensearch.hosts` |
| Blank screen / JS errors | Browser console; try clearing cache |
| Login loop | Check `opensearch_security` plugin and admin password |
| Index pattern missing | Rebuild via Settings → Index Patterns → `wazuh-alerts-*` |

---

### Agent Issues

See `references/agent-troubleshooting.md` for full per-OS detail.

**Quick Linux agent triage:**
```bash
systemctl status wazuh-agent
cat /var/ossec/logs/ossec.log | grep -E 'ERROR|WARN|connected|disconnected'
/var/ossec/bin/agent_control -l          # list all agents and status
/var/ossec/bin/agent_control -i <id>     # detail for specific agent
```

**Quick Windows agent triage (PowerShell):**
```powershell
Get-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
```

**Enrollment flow debug:**
```bash
# On manager — watch enrollment in real time
tail -f /var/ossec/logs/ossec.log | grep authd

# On agent — force re-enrollment
/var/ossec/bin/agent-auth -m <manager-ip> -A <agent-name>
```

**Agent stuck in "Disconnected":**
1. Verify port 1514 is reachable from agent: `nc -zv <manager> 1514`
2. Check `client.keys` on manager: `/var/ossec/etc/client.keys`
3. Check agent's `/var/ossec/etc/ossec.conf` — `<address>` must match manager IP/FQDN
4. Firewall: ensure UDP/TCP 1514 and TCP 1515 are open bidirectionally
5. Cert issues (4.3+): verify `<enrollment><server_ca_path>` points to valid CA

---

### Rules & Decoders

**Test rules interactively:**
```bash
/var/ossec/bin/wazuh-logtest
# Paste a raw log line; it shows decoder match + rule chain + alert output
```

**Locations:**
```
/var/ossec/ruleset/rules/           — Wazuh built-in rules (do not edit)
/var/ossec/etc/rules/               — Custom rules (edit here)
/var/ossec/ruleset/decoders/        — Built-in decoders
/var/ossec/etc/decoders/            — Custom decoders
```

**Rule debugging workflow:**
1. Copy suspect log line
2. Run `wazuh-logtest` — check which decoder fires
3. If no decoder match: write/fix decoder in `/var/ossec/etc/decoders/local_decoder.xml`
4. If decoder matches but no rule fires: check rule `<match>`, `<regex>`, `<field>` conditions
5. Reload: `systemctl reload wazuh-manager`

**Common rule/decoder pitfalls:**
- Decoder `<prematch>` must match before `<regex>` is evaluated
- Rules use POSIX extended regex — test with `echo "..." | grep -E 'pattern'`
- `<if_sid>` chains: parent rule must fire first
- Custom rules must use IDs ≥ 100000
- `<overwrite>` tag required to override built-in rules

---

### API

**Base URL:** `https://<manager>:55000`  
**Auth:**
```bash
TOKEN=$(curl -sk -u wazuh-wui:wazuh-wui -X POST \
  https://localhost:55000/security/user/authenticate | jq -r '.data.token')
```

**Common API checks:**
```bash
# Cluster status
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:55000/cluster/status

# Agent list
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:55000/agents?pretty

# Manager info
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:55000/manager/info

# Check API logs
journalctl -u wazuh-api -n 100
tail -f /var/ossec/logs/api.log
```

---

### Performance & Scaling

**Key metrics to monitor:**

```bash
# analysisd queue usage (should stay <80%)
grep 'Events dropped' /var/ossec/logs/ossec.log

# remoted stats
/var/ossec/bin/wazuh-control status
cat /var/ossec/var/run/wazuh-remoted.state

# Indexer indexing rate
curl -sk -u admin:admin https://localhost:9200/_nodes/stats/indices?pretty \
  | jq '.nodes[].indices.indexing'
```

**Tuning levers:**

| Bottleneck | Lever | Location |
|------------|-------|----------|
| analysisd dropping events | Increase `<queue_size>` | `ossec.conf` → `<analysisd>` |
| remoted buffer full | Increase `<recv_counter_flush>` | `ossec.conf` → `<remote>` |
| Indexer bulk rejections | Increase `thread_pool.write.queue_size` | `opensearch.yml` |
| JVM GC pressure | Tune heap, enable G1GC | `jvm.options` |
| Too many small shards | Increase `index.merge.policy` | ILM policy |
| High inode usage | Check `/var/ossec/queue/` accumulation | Disk + rotation config |

**Filebeat (ships alerts to indexer):**
```bash
systemctl status filebeat
filebeat test output          # test indexer connectivity
tail -f /var/log/filebeat/filebeat   # check for bulk rejection errors
```

---

### Multi-Node Cluster

**Config:** `/var/ossec/etc/ossec.conf` → `<cluster>` block

```xml
<cluster>
  <name>wazuh</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>supersecretkey16c</key>         <!-- must match on all nodes -->
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>master-ip</node>
  </nodes>
  <hidden>no</hidden>
  <disabled>no</disabled>
</cluster>
```

**Cluster diagnostics:**
```bash
# Check cluster connectivity
/var/ossec/bin/cluster_control -l          # list nodes
/var/ossec/bin/cluster_control --health    # health summary

# Common cluster issues
grep -i 'cluster\|ERROR' /var/ossec/logs/ossec.log | tail -50
grep -i 'cluster' /var/ossec/logs/cluster.log | tail -50
```

**Split-brain / nodes not joining:**
1. Verify `<key>` is identical on all nodes (exact match, no trailing whitespace)
2. Port 1516 open between all nodes
3. `<node_name>` must be unique per node
4. `<nodes><node>` must list master IP/FQDN; workers connect to master
5. Check SSL: `<ssl_agent_ca>` / `<ssl_agent_cert>` paths must be valid

---

### Certificates (4.3+ unified certs)

Wazuh 4.3+ uses a unified PKI for all internal TLS. Cert issues cause cascading failures.

```bash
# Check cert expiry
openssl x509 -in /etc/wazuh-indexer/certs/node.pem -noout -dates
openssl x509 -in /etc/wazuh-dashboard/certs/dashboard.pem -noout -dates

# Verify cert chain
openssl verify -CAfile /etc/wazuh-indexer/certs/root-ca.pem \
  /etc/wazuh-indexer/certs/node.pem

# Test indexer TLS
openssl s_client -connect localhost:9200 -CAfile /path/to/root-ca.pem
```

To regenerate certs: use `/usr/share/wazuh-certs-tool/wazuh-certs-tool.sh` — see `references/cert-renewal.md`.

---

## Reference Files

@wazuh_skills/references/log-locations.md
@wazuh_skills/references/agent-troubleshooting.md
@wazuh_skills/references/cert-renewal.md
@wazuh_skills/references/indexer-ops.md
@wazuh_skills/references/fim-sca.md
@wazuh_skills/references/log-ingestion.md