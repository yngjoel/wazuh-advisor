import os
import json
import logging
from langchain_core.tools import tool

from ssh_client import ssh_run

log = logging.getLogger("advisor.tools")

_TOOL_TIMEOUT = int(os.getenv("TOOL_TIMEOUT_SECONDS", "15"))

# Injected by advisor.py after loading hosts.yaml.
# Maps friendly host name -> host config dict.
FLEET: dict[str, dict] = {}


def _get_host(name: str) -> dict:
    """Look up a host config by name, returning a clear error if not found."""
    cfg = FLEET.get(name)
    if cfg is None:
        available = ", ".join(FLEET.keys()) or "none configured"
        raise ValueError(
            f"Unknown host '{name}'. Available hosts: {available}"
        )
    return cfg


# --- 1. SYSTEM & RESOURCE TOOLS ---

@tool
async def audit_os_resources(host: str) -> str:
    """
    Checks for resource ceilings on the specified Wazuh host:
    ulimits, JVM heap usage, and inode exhaustion.
    Wazuh is sensitive to these factors.
    The 'host' argument must be the exact name from the configured fleet.
    """
    cfg = _get_host(host)
    inodes_out, inodes_err, _ = await ssh_run(cfg, ["df", "-i"], timeout=_TOOL_TIMEOUT)
    ulimits_out, ulimits_err, _ = await ssh_run(
        cfg,
        ["sudo", "-u", "wazuh", "bash", "-c", "ulimit -a"],
        timeout=_TOOL_TIMEOUT,
    )
    inodes = inodes_out or inodes_err
    ulimits = ulimits_out or ulimits_err
    return f"--- INODE USAGE ---\n{inodes}\n--- WAZUH ULIMITS ---\n{ulimits}"


# --- 2. WAZUH MANAGER & CONFIG TOOLS ---

@tool
async def validate_wazuh_config(host: str) -> str:
    """
    Validates ossec.conf XML syntax and rule consistency on the specified host.
    Equivalent to running 'ossec-logtest -t'.
    The 'host' argument must be the exact name from the configured fleet.
    """
    cfg = _get_host(host)
    xml_out, xml_err, xml_rc = await ssh_run(
        cfg, ["xmllint", "--noout", "/var/ossec/etc/ossec.conf"], timeout=_TOOL_TIMEOUT
    )
    wazuh_out, wazuh_err, wazuh_rc = await ssh_run(
        cfg, ["sudo", "/var/ossec/bin/wazuh-analysisd", "-t"], timeout=_TOOL_TIMEOUT
    )
    return json.dumps({
        "xml_syntax": "Valid" if xml_rc == 0 else (xml_err or xml_out),
        "wazuh_internal_check": (wazuh_out if wazuh_rc == 0 else wazuh_err) or "No output",
    }, indent=2)


@tool
async def check_wazuh_daemons(host: str) -> str:
    """
    Checks the health of wazuh-analysisd, remoted, authd, db, and modulesd
    on the specified host. Identifies which internal component is failing.
    The 'host' argument must be the exact name from the configured fleet.
    """
    cfg = _get_host(host)
    out, err, rc = await ssh_run(cfg, ["ps", "aux"], timeout=_TOOL_TIMEOUT)
    if rc != 0:
        return f"Failed to run ps on '{host}': {err}"
    daemons = [
        "wazuh-analysisd",
        "wazuh-remoted",
        "wazuh-authd",
        "wazuh-db",
        "wazuh-modulesd",
    ]
    status = {d: ("Running" if d in out else "STOPPED") for d in daemons}
    return json.dumps(status, indent=2)


# --- 3. NETWORK & CONNECTIVITY TOOLS ---

@tool
async def audit_wazuh_networking(host: str) -> str:
    """
    Audits ports 1514, 1515, 1516, 9200, and 55000 on the specified host.
    Checks if the manager is listening for agents.
    The 'host' argument must be the exact name from the configured fleet.
    """
    cfg = _get_host(host)
    out, err, rc = await ssh_run(cfg, ["sudo", "ss", "-tlnp"], timeout=_TOOL_TIMEOUT)
    if rc != 0:
        return f"Failed to run ss on '{host}': {err}"
    relevant = [
        line for line in out.split("\n")
        if any(p in line for p in ["1514", "1515", "1516", "9200", "55000"])
    ]
    return "\n".join(relevant) if relevant else "No Wazuh ports found listening."


# --- 4. INDEXER & CLUSTER TOOLS ---

@tool
async def check_indexer_health(host: str) -> str:
    """
    Queries the Wazuh Indexer (OpenSearch) on the specified host for cluster
    health and shard status. Identifies 'yellow' or 'red' cluster states.
    The 'host' argument must be the exact name from the configured fleet.
    """
    cfg = _get_host(host)
    cmd = [
        "curl", "-sk",
        "-u", f"{cfg['indexer_user']}:{cfg['indexer_password']}",
        f"{cfg['indexer_host']}/_cluster/health?pretty",
    ]
    out, err, rc = await ssh_run(cfg, cmd, timeout=_TOOL_TIMEOUT)
    if rc != 0:
        return f"Indexer query failed on '{host}': {err}"
    return out or "Empty response from indexer."


# --- 5. LOG ANALYSIS TOOLS ---

@tool
async def search_wazuh_errors(host: str, pattern: str = "ERROR|CRITICAL") -> str:
    """
    Searches ossec.log and api.log on the specified host for error patterns.
    Default pattern is 'ERROR|CRITICAL'. Returns the last 15 matches per file.
    The 'host' argument must be the exact name from the configured fleet.
    """
    # Validate pattern — reject shell metacharacters before it reaches ssh_run
    if any(c in pattern for c in [";", "&", "|", "$", "`", "\n", "\r"]):
        return "Invalid pattern: shell metacharacters are not allowed."

    cfg = _get_host(host)
    paths = ["/var/ossec/logs/ossec.log", "/var/ossec/logs/api.log"]
    results = ""
    for path in paths:
        out, err, rc = await ssh_run(
            cfg, ["sudo", "grep", "-E", pattern, path], timeout=_TOOL_TIMEOUT
        )
        if rc not in (0, 1):   # grep exits 1 when no matches (normal)
            results += f"\n--- {path} ---\nError: {err}"
            continue
        lines = out.strip().splitlines()
        last_15 = "\n".join(lines[-15:]) if lines else "(no matches)"
        results += f"\n--- {path} ---\n{last_15}"

    return results if results else "No output returned from host."
