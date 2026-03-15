"""
ssh_client.py — Paramiko-based SSH session manager for the Wazuh fleet.

Each named host in hosts.yaml gets one persistent SSHClient in _pool.
If the transport drops, it is re-established transparently on the next call.
"""

import asyncio
import os
import stat
import shlex
import logging
import threading

import paramiko

log = logging.getLogger("advisor.ssh")

# Module-level connection pool: { host_name: paramiko.SSHClient }
_pool: dict[str, paramiko.SSHClient] = {}
_pool_lock = threading.Lock()

# Characters that must never appear in a command token passed to ssh_run.
# exec_command bypasses the remote shell, but we keep this as defense-in-depth.
_FORBIDDEN = {";", "&", "|", "$", "`", "\n", "\r", ">", "<"}


def check_key_permissions(fleet: dict[str, dict]) -> None:
    """
    Raise PermissionError if any SSH private key is group- or world-readable.
    Call this once at bot startup before accepting any user messages.
    """
    for name, cfg in fleet.items():
        path = os.path.expanduser(cfg["ssh_key"])
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"SSH key for host '{name}' not found: {path}"
            )
        mode = os.stat(path).st_mode
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            raise PermissionError(
                f"SSH key for '{name}' at {path} is group/world readable. "
                f"Run:  chmod 600 {path}"
            )


def _make_client(cfg: dict) -> paramiko.SSHClient:
    """Open a new authenticated SSHClient for the given host config."""
    client = paramiko.SSHClient()
    # RejectPolicy: refuse connections to hosts not in known_hosts.
    # Never use AutoAddPolicy in production — it defeats MITM protection.
    # Pre-populate known_hosts with: ssh-keyscan -H <host> >> ~/.ssh/known_hosts
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_system_host_keys()
    known_hosts = os.path.expanduser("~/.ssh/known_hosts")
    if os.path.isfile(known_hosts):
        client.load_host_keys(known_hosts)

    client.connect(
        hostname=cfg["hostname"],
        port=cfg.get("ssh_port", 22),
        username=cfg["ssh_user"],
        key_filename=os.path.expanduser(cfg["ssh_key"]),
        timeout=10,
        auth_timeout=10,
        banner_timeout=10,
        look_for_keys=False,   # use only the explicitly configured key
        allow_agent=False,     # no ssh-agent; deterministic auth
    )
    log.info("SSH connection established to '%s' (%s)", cfg["name"], cfg["hostname"])
    return client


def _get_client(cfg: dict) -> paramiko.SSHClient:
    """Return a live SSHClient from the pool, reconnecting if the transport dropped."""
    name = cfg["name"]
    with _pool_lock:
        client = _pool.get(name)
        transport_alive = (
            client is not None
            and client.get_transport() is not None
            and client.get_transport().is_active()
        )
        if not transport_alive:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
            client = _make_client(cfg)
            _pool[name] = client
    return client


def _ssh_run_sync(cfg: dict, cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    """Blocking SSH execution — called from a thread executor by ssh_run."""
    # Validate every token — reject shell metacharacters
    for token in cmd:
        if any(c in token for c in _FORBIDDEN):
            log.error("Rejected command token with metacharacter: %r", token)
            return "", f"Rejected unsafe command token: {token!r}", -1

    safe_cmd = " ".join(shlex.quote(t) for t in cmd)
    log.debug("ssh_run [%s]: %s", cfg["name"], safe_cmd)

    try:
        client = _get_client(cfg)
        _, stdout, stderr = client.exec_command(safe_cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        return out, err, exit_code
    except paramiko.AuthenticationException as e:
        log.error("SSH auth failed for '%s': %s", cfg["name"], e)
        return "", f"SSH authentication failed for '{cfg['name']}': {e}", -1
    except paramiko.SSHException as e:
        log.error("SSH error for '%s': %s", cfg["name"], e)
        # Remove from pool so next call gets a fresh connection attempt
        with _pool_lock:
            _pool.pop(cfg["name"], None)
        return "", f"SSH error on '{cfg['name']}': {e}", -1
    except Exception as e:
        log.exception("Unexpected SSH error for '%s'", cfg["name"])
        with _pool_lock:
            _pool.pop(cfg["name"], None)
        return "", str(e), -1


async def ssh_run(cfg: dict, cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    """
    Execute a command on a remote host via SSH without blocking the event loop.

    Args:
        cfg:     Host config dict (one entry from FLEET).
        cmd:     Command as a list of string tokens. Never pass shell=True.
        timeout: Per-command execution timeout in seconds.

    Returns:
        (stdout, stderr, exit_code)
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _ssh_run_sync, cfg, cmd, timeout)


def close_all() -> None:
    """Close all pooled SSH connections. Call on bot shutdown."""
    with _pool_lock:
        for name, client in list(_pool.items()):
            try:
                client.close()
                log.info("Closed SSH connection to '%s'", name)
            except Exception:
                pass
        _pool.clear()
