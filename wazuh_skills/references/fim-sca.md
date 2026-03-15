# FIM & SCA Deep Dive Reference

Comprehensive guide for File Integrity Monitoring and Security Configuration Assessment, including the YAML 2.0 migration required for Wazuh 4.8+.

---

## Table of Contents
1. [FIM Architecture](#fim-architecture)
2. [FIM Configuration Reference](#fim-config)
3. [FIM Troubleshooting](#fim-troubleshooting)
4. [SCA Architecture](#sca-architecture)
5. [SCA Configuration Reference](#sca-config)
6. [SCA YAML 2.0 Migration](#sca-migration)
7. [SCA Troubleshooting](#sca-troubleshooting)
8. [Custom Policy Authoring](#custom-policies)

---

## FIM Architecture {#fim-architecture}

FIM is handled by `wazuh-syscheckd`. It operates in two modes:

- **Scheduled scan**: Runs at `<frequency>` interval (default 12 hours). Full directory walk, compares against SQLite DB.
- **Realtime**: Uses inotify (Linux) / ReadDirectoryChangesW (Windows) for immediate change detection. Higher resource cost.

Database location: `/var/ossec/queue/db/<agent-id>.db`

Events flow: `syscheckd` → `wazuh-db` → `wazuh-analysisd` → alert

---

## FIM Configuration Reference {#fim-config}

### Full ossec.conf syscheck block
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>          <!-- scan interval in seconds (12 hours) -->
  <scan_on_start>yes</scan_on_start>    <!-- run scan when agent starts -->
  <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

  <!-- Linux paths with options -->
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">/etc/ssh,/etc/pam.d</directories>
  <directories check_all="yes" whodata="yes">/home</directories>  <!-- who-data: track user actions -->

  <!-- Windows paths -->
  <directories check_all="yes">%WINDIR%\System32</directories>
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>

  <!-- Ignore patterns -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore type="sregex">.log$|.tmp$|.swp$</ignore>

  <!-- Nodiff: track changes without storing diffs (large files) -->
  <nodiff>/etc/ssl/private</nodiff>

  <!-- Skip NFS/removable to avoid false positives -->
  <skip_nfs>yes</skip_nfs>
  <skip_dev>yes</skip_dev>
  <skip_proc>yes</skip_proc>
  <skip_sys>yes</skip_sys>

  <!-- Database limits -->
  <database>disk</database>             <!-- 'disk' or 'memory'; disk is safer for large deployments -->
  <process_priority>10</process_priority>
  <max_eps>100</max_eps>                <!-- max events/sec to prevent alert flooding -->
</syscheck>
```

### Attribute reference

| Attribute | Values | Effect |
|-----------|--------|--------|
| `check_all` | yes/no | Equivalent to all check_* attributes enabled |
| `check_md5sum` | yes/no | Verify MD5 hash |
| `check_sha1sum` | yes/no | Verify SHA1 hash |
| `check_sha256sum` | yes/no | Verify SHA256 hash |
| `check_size` | yes/no | Track file size |
| `check_owner` | yes/no | Track file owner |
| `check_group` | yes/no | Track file group |
| `check_perm` | yes/no | Track file permissions |
| `check_mtime` | yes/no | Track modification time |
| `check_inode` | yes/no | Track inode number |
| `realtime` | yes/no | Enable inotify/ReadDirectoryChangesW |
| `whodata` | yes/no | Enable audit integration (Linux: auditd; Windows: audit policy) |
| `report_changes` | yes/no | Include diff of changed files in alert |
| `recursion_level` | 0-320 | Max subdirectory depth (default: unlimited) |
| `follow_symbolic_links` | yes/no | Follow symlinks |
| `tags` | string | Custom tag added to FIM alerts for this directory |

---

## FIM Troubleshooting {#fim-troubleshooting}

### No FIM alerts at all
```bash
# 1. Confirm syscheck enabled
grep -A3 '<syscheck>' /var/ossec/etc/ossec.conf | grep disabled

# 2. Check syscheckd is running
grep 'syscheckd\|syscheck' /var/ossec/logs/ossec.log | tail -30

# 3. Force scan and watch
/var/ossec/bin/agent_control -r -u <agent-id>   # restart syscheck on agent
tail -f /var/ossec/logs/ossec.log | grep syscheck

# 4. Check FIM database exists for agent
ls -lh /var/ossec/queue/db/<agent-id>.db
```

### FIM scan never finishes
```bash
# Check how many files are being monitored (estimate)
find /etc /usr/bin /usr/sbin 2>/dev/null | wc -l

# If >500,000 files, reduce scope with recursion_level or ignore patterns
# Check current scan progress
grep 'Sending syscheck\|End of syscheck' /var/ossec/logs/ossec.log | tail -10
```

### Realtime FIM not working (Linux)
```bash
# Check inotify limits (default is often too low)
cat /proc/sys/fs/inotify/max_user_watches    # should be >524288

# Increase limit
sysctl -w fs.inotify.max_user_watches=524288
echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf

# Check current inotify usage
cat /proc/sys/fs/inotify/max_queued_events
```

### Who-data not working (Linux)
```bash
# Requires auditd
systemctl status auditd

# Check wazuh audit rules are loaded
auditctl -l | grep wazuh

# auditd must be running and Wazuh must have configured its rules
grep 'auditd\|whodata' /var/ossec/logs/ossec.log | tail -20
```

### FIM DB size growing out of control
```bash
# Check DB sizes per agent
ls -lhS /var/ossec/queue/db/*.db | head -20

# Vacuum DB (reclaim space)
/var/ossec/bin/wazuh-db vacuum agents

# If a specific agent DB is corrupted
systemctl stop wazuh-manager
rm /var/ossec/queue/db/<agent-id>.db
systemctl start wazuh-manager
```

---

## SCA Architecture {#sca-architecture}

SCA is handled by `wazuh-modulesd` (sca module). It:
1. Loads YAML policy files from `/var/ossec/ruleset/sca/` (built-in) and `/var/ossec/etc/shared/<group>/` (custom/shared)
2. Evaluates checks against local agent state
3. Sends results to manager → indexer → `wazuh-states-vulnerabilities-*` index

**Important**: SCA results are state-based, not event-based. They do not appear in `wazuh-alerts-*` — they're in their own index.

---

## SCA Configuration Reference {#sca-config}

### ossec.conf SCA block
```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <skip_nfs>yes</skip_nfs>
  <policies>
    <policy>/var/ossec/ruleset/sca/cis_ubuntu20-04.yml</policy>
    <policy>/var/ossec/etc/shared/custom_policy.yml</policy>
  </policies>
</sca>
```

### Built-in policy locations
```
/var/ossec/ruleset/sca/         — Wazuh-provided policies (do not edit)
/var/ossec/etc/shared/<group>/  — Custom/shared policies per agent group
```

---

## SCA YAML 2.0 Migration {#sca-migration}

Wazuh 4.8 introduced SCA YAML format 2.0. Policies in 1.0 format will silently fail or partially evaluate. **All custom policies must be migrated before upgrading to 4.8+.**

### Format comparison

**YAML 1.0 (4.6.x / 4.7.x)**
```yaml
policy:
  id: "custom_linux"
  file: "custom_linux.yml"
  name: "Custom Linux Policy"
  description: "Custom checks for Linux servers"
  references:
    - https://example.com

requirements:
  title: "Linux system"
  description: "Checks that this is a Linux system"
  condition: any
  rules:
    - 'f:/etc/os-release'

checks:
  - id: 1001
    title: "Ensure SSH root login is disabled"
    description: "Root login via SSH should be disabled"
    rationale: "Prevents direct root access"
    remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config"
    compliance:
      - cis: "5.2.8"
    condition: all
    rules:
      - 'f:/etc/ssh/sshd_config -> r:PermitRootLogin\s+no'
```

**YAML 2.0 (4.8+)**
```yaml
policy:
  id: "custom_linux"
  file: "custom_linux.yml"
  name: "Custom Linux Policy"
  description: "Custom checks for Linux servers"
  references:
    - https://example.com

requirements:
  title: "Linux system"
  description: "Checks that this is a Linux system"
  condition: any
  rules:
    - 'f:/etc/os-release'

checks:
  - id: 1001
    title: "Ensure SSH root login is disabled"
    description: "Root login via SSH should be disabled"
    rationale: "Prevents direct root access"
    remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config"
    compliance:
      - cis: ["5.2.8"]          # Now a list, not a string
    references:
      - "https://example.com"   # References moved here in 2.0
    condition: all
    rules:
      - 'f:/etc/ssh/sshd_config -> r:^\s*PermitRootLogin\s+no'
                                # Anchored regex recommended in 2.0
```

### Key format differences

| Element | YAML 1.0 | YAML 2.0 |
|---------|----------|----------|
| `compliance` values | `- cis: "5.2.8"` (string) | `- cis: ["5.2.8"]` (list) |
| `references` in check | Not supported | Supported as a list |
| Regex anchoring | Optional | Recommended (`^`) |
| `condition` values | `all`, `any`, `none` | Same, but `none` behavior refined |
| `rules` `type` field | Implicit | Can be explicit: `type: file` |

### Rule syntax reference (both versions)

```
# File exists
f:/path/to/file

# File contains regex
f:/path/to/file -> r:pattern

# File NOT containing regex
f:/path/to/file -> !r:pattern

# Command output matches
c:command -> r:expected_output

# Process running
p:process_name

# Directory exists
d:/path/to/dir

# Registry key (Windows)
r:HKEY_LOCAL_MACHINE\Key -> r:value_pattern
```

---

## SCA Troubleshooting {#sca-troubleshooting}

### No SCA results in dashboard
```bash
# 1. Check SCA module is running
grep 'sca' /var/ossec/logs/ossec.log | grep -E 'started|policy|scan' | tail -20

# 2. Check SCA index exists
curl -sk -u admin:admin https://localhost:9200/_cat/indices/wazuh-states-vulnerabilities-*?v

# 3. Force SCA rescan via API
TOKEN=$(curl -sk -u wazuh-wui:wazuh-wui -X POST \
  https://localhost:55000/security/user/authenticate | jq -r '.data.token')
curl -sk -XPUT -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/sca/<agent-id>/run"

# 4. Check policy loaded for agent
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/sca/<agent-id>" | jq '.data.affected_items'
```

### Policy loads but 0 checks pass/fail
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('/var/ossec/etc/shared/custom_policy.yml'))"

# Common issues:
# - Indentation errors (use spaces, never tabs)
# - YAML 1.0 syntax on 4.8+ manager
# - Requirements block failing (agent OS doesn't match)
# - Wrong file path in rules
```

### SCA results not syncing to agents in a cluster
```bash
# SCA policies shared via cluster sync
grep 'cluster' /var/ossec/logs/ossec.log | grep -i 'sca\|shared' | tail -20

# Check shared directory on master
ls -la /var/ossec/etc/shared/<group>/

# Force cluster sync
/var/ossec/bin/cluster_control --sync
```

---

## Custom Policy Authoring {#custom-policies}

### Minimal working policy template (YAML 2.0)
```yaml
policy:
  id: "custom_checks_v1"
  file: "custom_checks_v1.yml"
  name: "Custom Security Checks v1"
  description: "Organization-specific security baseline"

requirements:
  title: "Linux OS"
  description: "Target must be a Linux system"
  condition: any
  rules:
    - 'f:/etc/os-release -> r:linux'

checks:
  - id: 10001
    title: "Ensure /tmp is mounted with noexec"
    description: "Prevent execution from /tmp"
    rationale: "Attackers commonly use /tmp to stage payloads"
    remediation: "Add noexec to /tmp mount options in /etc/fstab"
    compliance:
      - cis: ["1.1.3"]
    condition: all
    rules:
      - 'c:mount -> r:/tmp.*noexec'

  - id: 10002
    title: "Ensure core dumps are restricted"
    description: "Core dumps should be disabled"
    rationale: "Core dumps can contain sensitive data"
    remediation: "Set * hard core 0 in /etc/security/limits.conf"
    condition: all
    rules:
      - 'f:/etc/security/limits.conf -> r:^\s*\*\s+hard\s+core\s+0'
      - 'f:/etc/sysctl.conf -> r:^\s*fs.suid_dumpable\s*=\s*0'
```

### Check ID ranges
- 1–99999: Reserved for Wazuh built-in policies
- 100000+: Custom policies

### Testing a custom policy
```bash
# Deploy policy to a test agent group
cp custom_checks_v1.yml /var/ossec/etc/shared/<test-group>/
systemctl reload wazuh-manager

# Force scan on test agent
curl -sk -XPUT -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/sca/<agent-id>/run"

# Check results after 60s
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/sca/<agent-id>/checks/custom_checks_v1" | jq '.data.affected_items[] | {id, title, result}'
```