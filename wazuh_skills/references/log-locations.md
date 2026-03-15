# Wazuh Log Locations & Verbosity

## Manager Logs

| File | Contains | Notes |
|------|----------|-------|
| `/var/ossec/logs/ossec.log` | All manager daemon messages | Primary triage target |
| `/var/ossec/logs/alerts/alerts.log` | JSON alert output | Every triggered rule |
| `/var/ossec/logs/alerts/alerts.json` | JSON alerts (structured) | Same as above, JSON format |
| `/var/ossec/logs/archives/archives.log` | All ingested events (if enabled) | Requires `<logall>yes</logall>` |
| `/var/ossec/logs/cluster.log` | Cluster sync messages | Multi-node only |
| `/var/ossec/logs/api.log` | REST API requests/responses | Also `journalctl -u wazuh-api` |
| `/var/ossec/logs/active-responses.log` | Active response executions | |
| `/var/ossec/logs/integrations.log` | Webhook/Slack/PagerDuty calls | |

## Indexer Logs

| File | Contains |
|------|----------|
| `/var/log/wazuh-indexer/wazuh-indexer.log` | Main OpenSearch log |
| `/var/log/wazuh-indexer/wazuh-indexer_deprecation.log` | API deprecation warnings |
| `/var/log/wazuh-indexer/wazuh-indexer_index_search_slowlog.log` | Slow query log |
| `/var/log/wazuh-indexer/wazuh-indexer_index_indexing_slowlog.log` | Slow indexing log |

## Dashboard Logs

```bash
journalctl -u wazuh-dashboard -f
# Config: /etc/wazuh-dashboard/opensearch_dashboards.yml
# logging.dest: stdout (default) or path to file
```

## Filebeat Logs

| File | Contains |
|------|----------|
| `/var/log/filebeat/filebeat` | Indexer connection, bulk errors |

Enable debug:
```bash
filebeat -e -d "*"   # verbose stderr output
```

## Agent Logs (Linux)

| File | Contains |
|------|----------|
| `/var/ossec/logs/ossec.log` | Agent daemon messages |
| `/var/ossec/logs/active-responses.log` | AR executions on agent |

## Agent Logs (Windows)

```
C:\Program Files (x86)\ossec-agent\ossec.log
C:\Program Files (x86)\ossec-agent\active-response\active-responses.log
```

## Increasing Verbosity

### Manager (ossec.conf)
```xml
<logging>
  <log_level>2</log_level>   <!-- 0=error, 1=warn, 2=info, 3=debug -->
</logging>
```

### Per-daemon debug (temporary, no restart needed):
```bash
/var/ossec/bin/wazuh-control debug    # toggle debug on all daemons
# Or target specific daemon:
kill -USR2 $(pidof wazuh-analysisd)   # toggle analysisd debug
```

### Indexer slow log thresholds
```bash
curl -sk -XPUT -u admin:admin https://localhost:9200/_settings \
  -H 'Content-Type: application/json' \
  -d '{
    "index.search.slowlog.threshold.query.warn": "5s",
    "index.indexing.slowlog.threshold.index.warn": "2s"
  }'
```

## Log Rotation & Retention

Manager rotates logs daily via `wazuh-monitord`. Config in `ossec.conf`:
```xml
<global>
  <alerts_log>yes</alerts_log>
  <logall>no</logall>          <!-- set yes to archive ALL events -->
  <logall_json>no</logall_json>
  <compress_alerts>no</compress_alerts>
  <logs_format>plain</logs_format>
</global>
```

Archives live in `/var/ossec/logs/alerts/YYYY/Mon/` — rotated and optionally gzipped.