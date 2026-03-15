# Wazuh Certificate Renewal (4.3+)

Wazuh 4.3+ uses a unified PKI. All components (indexer, dashboard, manager, Filebeat) share a root CA. Cert changes require coordinated restarts.

---

## Certificate Inventory

| Component | Cert path |
|-----------|-----------|
| Indexer node | `/etc/wazuh-indexer/certs/` |
| Dashboard | `/etc/wazuh-dashboard/certs/` |
| Filebeat | `/etc/filebeat/certs/` |
| Manager (cluster) | `/var/ossec/etc/sslmanager.cert` / `.key` |
| Agent enrollment (authd) | `/var/ossec/etc/sslmanager.cert` / `.key` |

---

## Check Expiry

```bash
# Indexer
openssl x509 -in /etc/wazuh-indexer/certs/node.pem -noout -dates

# Dashboard
openssl x509 -in /etc/wazuh-dashboard/certs/dashboard.pem -noout -dates

# Filebeat
openssl x509 -in /etc/filebeat/certs/filebeat.pem -noout -dates

# Root CA
openssl x509 -in /etc/wazuh-indexer/certs/root-ca.pem -noout -dates
```

---

## Regenerate All Certs (wazuh-certs-tool)

**This replaces ALL certs — plan for downtime.**

```bash
# 1. Download tool (if not present)
curl -sO https://packages.wazuh.com/4.x/wazuh-install-files.tar
tar -xf wazuh-install-files.tar

# 2. Edit config.yml — define your node names/IPs
cat config.yml
# nodes:
#   indexer:
#     - name: node-1
#       ip: 192.168.1.10
#   server:
#     - name: wazuh-1
#       ip: 192.168.1.10
#   dashboard:
#     - name: dashboard
#       ip: 192.168.1.10

# 3. Generate certs
bash /usr/share/wazuh-certs-tool/wazuh-certs-tool.sh -A

# Output: ./wazuh-certificates/ containing all certs
```

---

## Install New Certs

### Indexer
```bash
# Stop indexer
systemctl stop wazuh-indexer

# Backup
cp -rp /etc/wazuh-indexer/certs /etc/wazuh-indexer/certs.bak

# Install
cp wazuh-certificates/node-1.pem /etc/wazuh-indexer/certs/node.pem
cp wazuh-certificates/node-1-key.pem /etc/wazuh-indexer/certs/node-key.pem
cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/root-ca.pem
cp wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/admin.pem
cp wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem

# Fix ownership
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*

systemctl start wazuh-indexer
```

### Dashboard
```bash
systemctl stop wazuh-dashboard

cp wazuh-certificates/dashboard.pem /etc/wazuh-dashboard/certs/
cp wazuh-certificates/dashboard-key.pem /etc/wazuh-dashboard/certs/
cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/

chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs/

systemctl start wazuh-dashboard
```

### Filebeat
```bash
systemctl stop filebeat

cp wazuh-certificates/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
cp wazuh-certificates/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/root-ca.pem

chown root:root /etc/filebeat/certs/*

systemctl start filebeat
```

---

## Verify New Certs

```bash
# Indexer responding with new cert?
openssl s_client -connect localhost:9200 -CAfile /etc/wazuh-indexer/certs/root-ca.pem 2>&1 | grep -E 'subject|issuer|notAfter'

# Dashboard TLS
openssl s_client -connect localhost:443 2>&1 | grep -E 'subject|notAfter'

# Indexer cluster health
curl -sk -u admin:admin https://localhost:9200/_cluster/health?pretty

# Filebeat can ship to indexer
filebeat test output
```

---

## Security Plugin — Re-initialize (if needed after root CA change)

If you replaced the root CA (not just leaf certs), the security plugin must be re-initialized:

```bash
# Run security admin script
JAVA_HOME=/usr/share/wazuh-indexer/jdk \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ \
  -icl \
  -p 9300 \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -nhnv
```

---

## Agent Enrollment Cert (authd)

Used for agent auto-enrollment. In `ossec.conf`:
```xml
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_source_ip>no</use_source_ip>
  <ssl_agent_ca>/var/ossec/etc/rootCA.pem</ssl_agent_ca>
  <ssl_verify_host>no</ssl_verify_host>
  <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
  <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
</auth>
```

Regenerate authd cert (self-signed):
```bash
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /var/ossec/etc/sslmanager.key \
  -out /var/ossec/etc/sslmanager.cert \
  -subj "/CN=wazuh-manager"

chown root:ossec /var/ossec/etc/sslmanager.*
chmod 640 /var/ossec/etc/sslmanager.*
systemctl restart wazuh-manager
```