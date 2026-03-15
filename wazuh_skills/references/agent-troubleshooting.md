# Agent Troubleshooting — Per-OS Deep Dive

## Contents
1. [Linux Agents](#linux)
2. [Windows Agents](#windows)
3. [Containers & Kubernetes](#kubernetes)

---

## Linux Agents {#linux}

### Installation paths
```
/var/ossec/              — agent home
/var/ossec/etc/ossec.conf — agent config
/var/ossec/etc/client.keys — enrolled key (single line)
/var/ossec/logs/ossec.log  — agent log
/var/ossec/bin/            — binaries
```

### Connection state machine
```
PENDING → ENROLLING → ACTIVE → DISCONNECTED
```
- `PENDING`: key exists in manager, agent not yet connected
- `ENROLLING`: authd handshake in progress
- `ACTIVE`: agent heartbeating every 10s (default)
- `DISCONNECTED`: missed heartbeats > `<agents_disconnection_time>`

### Full Linux agent debug workflow

```bash
# 1. Check agent service
systemctl status wazuh-agent

# 2. Check config validity
/var/ossec/bin/wazuh-control config-check 2>&1

# 3. Verify manager connectivity
nc -zv <manager-ip> 1514   # agent comms
nc -zv <manager-ip> 1515   # enrollment

# 4. Check key
cat /var/ossec/etc/client.keys   # format: <id> <name> <ip> <key>

# 5. Force re-enrollment (destroys old key)
systemctl stop wazuh-agent
rm /var/ossec/etc/client.keys
/var/ossec/bin/agent-auth -m <manager-ip> -A $(hostname)
systemctl start wazuh-agent

# 6. Real-time log watch
tail -f /var/ossec/logs/ossec.log

# 7. Check FIM database (if FIM issues)
/var/ossec/bin/fim_db_tool -p    # print FIM DB entries
```

### FIM (File Integrity Monitoring) — Linux

Config in `ossec.conf`:
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>
  <directories check_all="yes" report_changes="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>
  <ignore>/etc/mtab</ignore>
</syscheck>
```

FIM not alerting:
1. Check `<disabled>` is `no`
2. Verify `realtime="yes"` for live monitoring (otherwise waits for scheduled scan)
3. Check inotify limits: `cat /proc/sys/fs/inotify/max_user_watches` — increase if low:
   ```bash
   echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf && sysctl -p
   ```
4. Check FIM DB: `/var/ossec/queue/fim/db/`

### SCA (Security Configuration Assessment) — Linux

```bash
# Force SCA scan
/var/ossec/bin/wazuh-control restart   # triggers SCA on startup

# SCA results in API
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/sca/<agent-id>/checks/<policy-id>?pretty"

# SCA logs
grep 'sca' /var/ossec/logs/ossec.log
```

---

## Windows Agents {#windows}

### Installation paths
```
C:\Program Files (x86)\ossec-agent\
C:\Program Files (x86)\ossec-agent\ossec.conf
C:\Program Files (x86)\ossec-agent\client.keys
C:\Program Files (x86)\ossec-agent\ossec.log
```

### Service management (PowerShell as Admin)
```powershell
Get-Service WazuhSvc
Start-Service WazuhSvc
Stop-Service WazuhSvc
Restart-Service WazuhSvc

# Service details
sc qc WazuhSvc
sc queryex WazuhSvc
```

### Full Windows debug workflow

```powershell
# 1. Check service
Get-Service WazuhSvc | Select-Object Status, StartType

# 2. Tail agent log
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100 -Wait

# 3. Test manager connectivity
Test-NetConnection -ComputerName <manager-ip> -Port 1514
Test-NetConnection -ComputerName <manager-ip> -Port 1515

# 4. Check Windows Firewall rules
Get-NetFirewallRule -DisplayName "*Wazuh*"
# Or check inbound/outbound for ports 1514/1515

# 5. Force re-enrollment
Stop-Service WazuhSvc
Remove-Item "C:\Program Files (x86)\ossec-agent\client.keys"
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m <manager-ip>
Start-Service WazuhSvc
```

### Windows Event Log collection

Default config collects System, Security, Application. Extend:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Verify Wazuh can read a channel:
```powershell
wevtutil qe "Security" /c:1 /f:text   # if this works, Wazuh can too
```

Common Windows agent failures:
| Symptom | Cause | Fix |
|---------|-------|-----|
| Service starts then stops | Config XML error | Check ossec.conf for malformed XML |
| "Invalid key" in log | Key mismatch | Re-enroll |
| No Windows events in dashboard | `<log_format>` wrong | Use `eventchannel` not `syslog` for WEL |
| FIM not working | AV exclusion needed | Exclude `ossec-agent\` in AV |
| High CPU | Too many realtime FIM paths | Reduce realtime dirs, use scheduled scan |

### FIM on Windows

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <directories check_all="yes" realtime="yes">%WINDIR%\System32</directories>
  <directories check_all="yes">%PROGRAMFILES%</directories>
  <ignore>%WINDIR%\System32\LogFiles</ignore>
  <ignore type="sregex">.log$|.htm$|.jpg$</ignore>
</syscheck>
```

---

## Containers & Kubernetes {#kubernetes}

### Deployment patterns

**Pattern A — Sidecar (DaemonSet)**  
Each node runs a Wazuh agent pod. Recommended for full host-level visibility.

**Pattern B — Wazuh agent on host**  
Agent installed directly on K8s worker nodes (not in container). Simpler, more reliable FIM.

**Pattern C — Log shipper only**  
Use Filebeat/Fluentd to forward container logs to Wazuh manager without a traditional agent.

### DaemonSet agent troubleshooting

```bash
# Check all agent pods
kubectl get pods -n wazuh -l app=wazuh-agent

# Logs for specific pod
kubectl logs -n wazuh <pod-name> --tail=100

# Exec into agent pod
kubectl exec -it -n wazuh <pod-name> -- /bin/bash

# Inside pod — same Linux commands apply
cat /var/ossec/logs/ossec.log
/var/ossec/bin/agent_control -l
```

### Common K8s agent issues

**Agent can't reach manager:**
```bash
# From agent pod, test connectivity
kubectl exec -it -n wazuh <pod> -- nc -zv <manager-svc> 1514
kubectl exec -it -n wazuh <pod> -- nc -zv <manager-svc> 1515

# Check NetworkPolicy — must allow egress on 1514/1515
kubectl get networkpolicy -n wazuh
```

**Environment variables for agent config:**
```yaml
env:
  - name: WAZUH_MANAGER
    value: "wazuh-manager-svc"
  - name: WAZUH_AGENT_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
  - name: WAZUH_REGISTRATION_SERVER
    value: "wazuh-manager-svc"
```

**Persistent enrollment (survives pod restarts):**
Mount a PVC or ConfigMap to persist `/var/ossec/etc/client.keys`. Without this, every pod restart triggers re-enrollment and creates a new agent entry.

```yaml
volumeMounts:
  - name: agent-keys
    mountPath: /var/ossec/etc/client.keys
    subPath: client.keys
volumes:
  - name: agent-keys
    persistentVolumeClaim:
      claimName: wazuh-agent-keys-pvc
```

**Container log collection (no sidecar):**
```xml
<!-- In manager ossec.conf or use logcollector on node agent -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/containers/*.log</location>
</localfile>
```

### Wazuh Manager on Kubernetes

If the manager itself runs in K8s:

```bash
# Manager pod health
kubectl get pods -n wazuh -l app=wazuh-manager
kubectl logs -n wazuh <manager-pod> --tail=200

# Check PVC for ossec data
kubectl get pvc -n wazuh

# Services
kubectl get svc -n wazuh
# Must expose: 1514 (NodePort or LoadBalancer), 1515, 55000, 9200, 443
```

**StatefulSet vs Deployment:**  
Manager must be a StatefulSet with stable storage. Running as a plain Deployment risks data loss on reschedule.

**Resource requests — minimum viable:**
```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "500m"
  limits:
    memory: "4Gi"
    cpu: "2000m"
```
Indexer needs minimum 4Gi RAM; set JVM heap to 50% of limit.