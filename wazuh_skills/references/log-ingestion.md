# Log Ingestion Reference

Syslog, CEF, JSON, Filebeat, and custom integration configuration for Wazuh.

---

## Table of Contents
1. [Ingestion Architecture](#architecture)
2. [Syslog (UDP/TCP)](#syslog)
3. [CEF Ingestion](#cef)
4. [JSON Log Files](#json)
5. [Filebeat (4.6.x/4.7.x)](#filebeat)
6. [Custom Decoders](#custom-decoders)
7. [Third-Party Integrations](#integrations)
8. [Performance Tuning](#performance)

---

## Ingestion Architecture {#architecture}

```
External devices / apps
        │
        ├─ Syslog (UDP 514 / TCP 514) ──────► wazuh-remoted ──► wazuh-analysisd
        │
        ├─ Log files (agent) ───────────────► wazuh-logcollector ──► wazuh-analysisd
        │
        ├─ Filebeat (4.6/4.7) ─────────────► wazuh-indexer (OpenSearch)
        │
        └─ Wazuh Server (4.8+) ────────────► wazuh-indexer (integrated)
```

Events enter `wazuh-analysisd`, go through decoders → rules → alert output.
Alerts are written to `alerts.json` then shipped to indexer.

---

## Syslog (UDP/TCP) {#syslog}

### Manager ossec.conf — enable syslog receiver
```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.0.0.0/8</allowed-ips>   <!-- restrict to your network -->
  <local_ip>0.0.0.0</local_ip>
</remote>

<!-- Add a second block for TCP -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.0.0.0/8</allowed-ips>
</remote>
```

### Verify syslog is being received
```bash
# remoted listening on 514
ss -ulnp | grep 514
ss -tlnp | grep 514

# Live incoming event watch
tail -f /var/ossec/logs/archives/archives.log | grep <source-ip>

# Count events from specific IP in last minute
grep $(date '+%Y %b %d %H:%M') /var/ossec/logs/archives/archives.log | \
  grep <source-ip> | wc -l
```

### Syslog troubleshooting

| Symptom | Check |
|---------|-------|
| No events arriving | `ss -ulnp \| grep 514` — confirm remoted listening |
| Events in archives but no alerts | No decoder matching — run `wazuh-logtest` |
| `Permission denied` on port 514 | Port <1024 requires root or CAP_NET_BIND_SERVICE |
| Events dropped | `allowed-ips` mismatch — check source IP vs config |
| Duplicate events | Device sending to multiple remotes or both UDP/TCP |

### Using a non-root port (recommended)
```xml
<!-- Use 1514 for syslog to avoid privilege issues -->
<remote>
  <connection>syslog</connection>
  <port>1514</port>
  <protocol>udp</protocol>
  <allowed-ips>0.0.0.0/0</allowed-ips>
</remote>
```
Then configure sending devices to forward to port 1514.

---

## CEF Ingestion {#cef}

CEF (Common Event Format) is a syslog-based format used by ArcSight, Palo Alto, Fortinet, and others.

CEF format: `CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`

### Built-in CEF decoders
Wazuh includes decoders for many vendors. Check:
```bash
ls /var/ossec/ruleset/decoders/ | grep -E 'cef|palo|fortinet|checkpoint'
```

### Test CEF decoding
```bash
/var/ossec/bin/wazuh-logtest
# Paste a raw CEF line, e.g.:
# Jan 15 12:00:00 firewall CEF:0|Palo Alto Networks|PAN-OS|9.0|THREAT|url|1|src=1.2.3.4 dst=4.3.2.1 ...
```

### Custom CEF decoder template
```xml
<!-- /var/ossec/etc/decoders/local_decoder.xml -->
<decoder name="cef-custom-vendor">
  <prematch>CEF:0|CustomVendor|</prematch>
</decoder>

<decoder name="cef-custom-vendor-fields">
  <parent>cef-custom-vendor</parent>
  <regex>src=(\d+\.\d+\.\d+\.\d+) dst=(\d+\.\d+\.\d+\.\d+) spt=(\d+)</regex>
  <order>srcip, dstip, srcport</order>
</decoder>
```

---

## JSON Log Files {#json}

Wazuh can ingest JSON-formatted log files directly via logcollector.

### logcollector JSON config (agent ossec.conf)
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/myapp/events.json</location>
  <label key="integration">myapp</label>
  <label key="env">production</label>
</localfile>
```

### Multi-line JSON (newline-delimited)
Wazuh handles one JSON object per line by default. For multi-line JSON:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/myapp/events.json</location>
  <multiline_regex>^\{</multiline_regex>    <!-- start of new JSON object -->
</localfile>
```

### JSON ingestion troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| JSON fields not in alert | JSON decoder not extracting | Use `wazuh-logtest` to verify decoder is firing |
| `json_null_field` errors in log | Null values in JSON | Add `<json_null_field>discard</json_null_field>` to `<global>` block |
| JSON partially parsed | Nested objects | Write custom decoder for nested keys |
| Log file not being read | Path/permissions issue | `ls -la <log-path>`; wazuh-logcollector runs as wazuh user |
| Events in logcollector but no alert | No rule matching extracted fields | Write custom rule using decoded field names |

### Extracting nested JSON fields (decoder)
```xml
<decoder name="myapp-json">
  <program_name>myapp</program_name>
  <json_null_field>discard</json_null_field>
</decoder>
```

Nested fields are accessible as `data.field.subfield` in rules:
```xml
<rule id="100500" level="10">
  <decoded_as>myapp-json</decoded_as>
  <field name="data.event_type">login_failure</field>
  <description>MyApp: Login failure detected</description>
</rule>
```

---

## Filebeat (4.6.x / 4.7.x) {#filebeat}

Filebeat ships `alerts.json` from the manager to the indexer. It is replaced by the integrated pipeline in 4.8+.

### Key config file
`/etc/filebeat/filebeat.yml`

### Test and troubleshoot
```bash
# Test connectivity to indexer
filebeat test output

# Test config syntax
filebeat test config

# Live log
tail -f /var/log/filebeat/filebeat

# Common errors to look for
grep -E 'error|rejected|failed|timeout' /var/log/filebeat/filebeat | tail -30
```

### Common Filebeat issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `connection refused` to indexer | Indexer down or cert issue | Check indexer status; verify `hosts` and `ssl` in filebeat.yml |
| `bulk rejected` errors | Indexer write queue full | Fix indexer first (disk, watermark, thread pool); Filebeat will retry |
| Alerts not appearing in dashboard | Filebeat not running | `systemctl status filebeat`; `systemctl start filebeat` |
| Index template not applied | Setup not run post-install | `filebeat setup --index-management` |
| Duplicate alerts | Filebeat registry corrupted | `rm /var/lib/filebeat/registry`; restart Filebeat (re-sends recent alerts) |
| TLS handshake failure | Cert CN/SAN mismatch | Verify indexer cert SANs include the hostname in `hosts:` |

### Filebeat config reference
```yaml
# /etc/filebeat/filebeat.yml (key sections)
output.elasticsearch:
  hosts: ["https://<indexer-ip>:9200"]
  protocol: https
  username: admin
  password: admin
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: /etc/filebeat/certs/filebeat.pem
  ssl.key: /etc/filebeat/certs/filebeat-key.pem

setup.template.json.enabled: true
setup.template.json.path: /etc/filebeat/wazuh-template.json
setup.template.json.name: wazuh
setup.ilm.overwrite: true
```

### Check Filebeat in 4.8+ (should be gone)
```bash
# After upgrading to 4.8+, Filebeat should be stopped and disabled
systemctl status filebeat    # should be inactive/disabled
# Do NOT remove until confirmed wazuh-server is shipping data
curl -sk -u admin:admin https://localhost:9200/_cat/indices/wazuh-alerts-*?v | head -5
```

---

## Custom Decoders {#custom-decoders}

### Decoder file location
```
/var/ossec/etc/decoders/local_decoder.xml   — primary custom decoder file
```

### Decoder anatomy
```xml
<!-- Stage 1: Identify the log source (prematch) -->
<decoder name="mydevice">
  <prematch>MyDevice:</prematch>
</decoder>

<!-- Stage 2: Extract fields from matched logs -->
<decoder name="mydevice-fields">
  <parent>mydevice</parent>
  <regex>action=(\w+) src=(\S+) user=(\S+)</regex>
  <order>action, srcip, user</order>
</decoder>
```

### Testing decoders
```bash
/var/ossec/bin/wazuh-logtest
# Enter a sample log line; output shows:
# Phase 1: Which decoder matched
# Phase 2: What fields were extracted
# Phase 3: Which rule fired (if any)
```

### Common decoder pitfalls
- `<prematch>` is regex, not literal string — escape special chars: `\.`, `\(`
- `<regex>` uses POSIX ERE — test with `echo "line" | grep -E 'pattern'`
- Field order in `<order>` must match capture group order in `<regex>`
- Parent decoder must fire before child decoder is evaluated
- `<program_name>` matches the syslog program field, not the message body

### Standard decoded field names (used in rules)
```
srcip        — source IP address
dstip        — destination IP address
srcport      — source port
dstport      — destination port
protocol     — network protocol
action       — log action (allow, deny, block, etc.)
user         — username
url          — URL
id           — event ID
status       — status code
data         — generic data field
extra_data   — additional data
```

---

## Third-Party Integrations {#integrations}

### ossec.conf integration block
```xml
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/YOUR/WEBHOOK/URL</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>

<integration>
  <name>pagerduty</name>
  <api_key>YOUR_PAGERDUTY_API_KEY</api_key>
  <level>12</level>
</integration>
```

### Integration script locations
```
/var/ossec/integrations/          — built-in integration scripts
/var/ossec/integrations/custom-*  — custom integration scripts (prefix with 'custom-')
```

### Custom integration script template (Python)
```python
#!/usr/bin/env python3
# /var/ossec/integrations/custom-myapp

import json
import sys
import requests

alert_file = sys.argv[1]
api_key = sys.argv[2] if len(sys.argv) > 2 else ''

with open(alert_file) as f:
    alert = json.load(f)

level = alert.get('rule', {}).get('level', 0)
description = alert.get('rule', {}).get('description', 'Unknown')
agent = alert.get('agent', {}).get('name', 'Unknown')

# Send to your system
payload = {
    "text": f"[Level {level}] {description} on {agent}"
}
requests.post("https://your-endpoint.com/webhook", json=payload)
```

Make executable: `chmod +x /var/ossec/integrations/custom-myapp`

---

## Performance Tuning {#performance}

### High event volume — analysisd queue
```xml
<!-- ossec.conf — increase analysisd queue -->
<analysisd>
  <queue_size>131072</queue_size>    <!-- default: 16384 -->
</analysisd>
```

### High syslog volume — remoted buffer
```xml
<!-- ossec.conf -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <queue_size>131072</queue_size>
</remote>
```

### Monitor for event drops
```bash
# Check if analysisd is dropping events
grep -E 'Events dropped|queue.*full' /var/ossec/logs/ossec.log | tail -20

# Check remoted state
cat /var/ossec/var/run/wazuh-remoted.state

# Key metrics from remoted state:
# - recv_evt_count: events received
# - discarded_count: events discarded (queue full)
```

### Logcollector rate limiting (per agent)
```xml
<!-- Prevent a noisy log file from flooding the pipeline -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/noisy-app.log</location>
  <max_size>50MB</max_size>          <!-- skip file rotation detection above this size -->
  <label key="source">noisy-app</label>
</localfile>
```