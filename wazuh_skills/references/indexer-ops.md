# Wazuh Indexer Operations

## Index Management

### Key indices
```
wazuh-alerts-*        — alert data (ILM managed)
wazuh-archives-*      — raw events (if archiving enabled)
wazuh-states-*        — agent state snapshots (4.4+)
.opendistro-*         — security plugin internal indices
.kibana_*             — dashboard saved objects
```

### Index health
```bash
# Full index listing with health/size/docs
curl -sk -u admin:admin https://localhost:9200/_cat/indices?v&h=health,status,index,pri,rep,docs.count,store.size

# Check mapping for an index
curl -sk -u admin:admin https://localhost:9200/wazuh-alerts-4.x-YYYY.MM.DD/_mapping?pretty

# Index settings
curl -sk -u admin:admin https://localhost:9200/wazuh-alerts-4.x-YYYY.MM.DD/_settings?pretty
```

### Unassigned shard diagnosis
```bash
# Why are shards unassigned?
curl -sk -XGET -u admin:admin https://localhost:9200/_cluster/allocation/explain?pretty

# Force reroute (use with care)
curl -sk -XPOST -u admin:admin https://localhost:9200/_cluster/reroute?retry_failed=true
```

### Delete old indices (manual cleanup)
```bash
# List indices older than 90 days
curl -sk -u admin:admin "https://localhost:9200/_cat/indices/wazuh-alerts-*?v&s=index" | grep -v $(date +%Y)

# Delete a specific index
curl -sk -XDELETE -u admin:admin https://localhost:9200/wazuh-alerts-4.x-2024.01.01
```

---

## ILM (Index Lifecycle Management)

### Check current ILM policy
```bash
curl -sk -u admin:admin https://localhost:9200/_ilm/policy/wazuh-alerts?pretty
```

### Default Wazuh ILM rollover conditions
- Index age: 7 days  
- Index size: 50GB

### Modify ILM policy (example: extend to 30 days)
```bash
curl -sk -XPUT -u admin:admin https://localhost:9200/_ilm/policy/wazuh-alerts \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": {
      "phases": {
        "hot": {
          "actions": {
            "rollover": {
              "max_age": "30d",
              "max_size": "50gb"
            }
          }
        },
        "delete": {
          "min_age": "90d",
          "actions": {
            "delete": {}
          }
        }
      }
    }
  }'
```

### Force ILM rollover now
```bash
curl -sk -XPOST -u admin:admin \
  "https://localhost:9200/wazuh-alerts-4.x/_rollover" \
  -H 'Content-Type: application/json' -d '{}'
```

### ILM stuck / not progressing
```bash
# Check ILM explain for an index
curl -sk -u admin:admin \
  "https://localhost:9200/wazuh-alerts-4.x-YYYY.MM.DD/_ilm/explain?pretty"

# Retry failed ILM step
curl -sk -XPOST -u admin:admin \
  "https://localhost:9200/wazuh-alerts-4.x-YYYY.MM.DD/_ilm/retry"
```

---

## Snapshot / Restore

### Register S3 snapshot repo
```bash
curl -sk -XPUT -u admin:admin https://localhost:9200/_snapshot/wazuh-backups \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "s3",
    "settings": {
      "bucket": "my-wazuh-backups",
      "region": "us-east-1",
      "base_path": "snapshots"
    }
  }'
```

### Register local filesystem repo
```bash
# Must add path to opensearch.yml first:
# path.repo: ["/mnt/snapshots"]
curl -sk -XPUT -u admin:admin https://localhost:9200/_snapshot/local-backup \
  -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/mnt/snapshots"}}'
```

### Take snapshot
```bash
curl -sk -XPUT -u admin:admin \
  "https://localhost:9200/_snapshot/local-backup/snapshot-$(date +%Y%m%d)?wait_for_completion=true" \
  -H 'Content-Type: application/json' \
  -d '{"indices":"wazuh-alerts-*","ignore_unavailable":true}'
```

### Restore snapshot
```bash
# Close index first if it exists
curl -sk -XPOST -u admin:admin https://localhost:9200/wazuh-alerts-4.x-2024.01.01/_close

# Restore
curl -sk -XPOST -u admin:admin \
  "https://localhost:9200/_snapshot/local-backup/snapshot-20240101/_restore" \
  -H 'Content-Type: application/json' \
  -d '{"indices":"wazuh-alerts-4.x-2024.01.01","ignore_unavailable":true}'
```

---

## Reindex

Use when migrating to a new mapping or recovering corrupted indices:

```bash
curl -sk -XPOST -u admin:admin https://localhost:9200/_reindex \
  -H 'Content-Type: application/json' \
  -d '{
    "source": {"index": "wazuh-alerts-4.x-2024.01.01"},
    "dest": {"index": "wazuh-alerts-4.x-2024.01.01-reindexed"}
  }'
```

---

## Performance Tuning

### JVM heap (50% RAM, max 32g)
```
# /etc/wazuh-indexer/jvm.options
-Xms4g
-Xmx4g
-XX:+UseG1GC
-XX:G1HeapRegionSize=4m
-XX:InitiatingHeapOccupancyPercent=30
```

### Thread pool sizing
```yaml
# opensearch.yml
thread_pool.write.queue_size: 10000
thread_pool.search.queue_size: 10000
```

### Disable swapping
```bash
# Temporary
sudo swapoff -a

# Permanent
echo 'vm.swappiness=1' >> /etc/sysctl.conf && sysctl -p

# In opensearch.yml
bootstrap.memory_lock: true
```

### Bulk indexing performance check
```bash
curl -sk -u admin:admin https://localhost:9200/_nodes/stats/thread_pool?pretty \
  | jq '.nodes[].thread_pool.write'
# Look for: "rejected" counter — should be 0 or very low
```