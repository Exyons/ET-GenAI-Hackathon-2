"""Response playbooks for Linux hosts. Stdlib only. Dry-run builds the exact
command(s); armed actually runs them. Reversible playbooks accept undo=True.

Safety: run() only really executes when the action is `armed` AND the agent was
started with PRAHARI_ALLOW_ARMED=true. Otherwise it reports what it WOULD do.
Read-only playbooks (snapshot) always run — they cannot harm the host.
"""
from __future__ import annotations

import shlex
import subprocess

# keep the management port reachable so isolating a host never locks the operator out
MGMT_PORT = "22"
READ_ONLY = {"snapshot"}
TABLE = "inet prahari"


def build_commands(playbook: str, target: str, undo: bool) -> list[str]:
    t = shlex.quote(target)
    if playbook == "isolate_host":
        if undo:
            return [f"nft delete table {TABLE}"]
        return [
            f"nft add table {TABLE}",
            f"nft add chain {TABLE} out '{{ type filter hook output priority 0 ; policy drop ; }}'",
            f"nft add rule {TABLE} out ct state established,related accept",
            f"nft add rule {TABLE} out oifname lo accept",
            f"nft add rule {TABLE} out tcp dport {MGMT_PORT} accept",
        ]
    if playbook == "block_ip":
        if undo:
            return [f"nft delete element {TABLE} blocked {{ {t} }}"]
        return [
            f"nft add table {TABLE}",
            f"nft add set {TABLE} blocked '{{ type ipv4_addr ; }}'",
            f"nft add chain {TABLE} out '{{ type filter hook output priority 0 ; }}'",
            f"nft add rule {TABLE} out ip daddr @blocked drop",
            f"nft add element {TABLE} blocked {{ {t} }}",
        ]
    if playbook == "disable_account":
        return [f"usermod -U {t}"] if undo else [f"usermod -L {t}"]
    if playbook == "kill_process":
        return [] if undo else [f"pkill -f {t}"]
    if playbook == "snapshot":
        # collected in-process by forensics_linux (see run) — this string is only
        # what the audit log shows the operator
        return ["prahari forensics — /proc socket→pid→exe attribution (read-only)"]
    return []


def _snapshot(action: dict) -> dict:
    """Targeted forensics. Read-only, so it runs even in dry-run — and it is fed
    the incident's own IOCs so it answers 'which process owns that C2 socket'
    rather than dumping ps aux."""
    params = action.get("params") or {}
    try:
        import forensics_linux
    except ImportError as e:  # collector deployed without the module
        return {"ran": False, "dry_run": True, "command": build_commands("snapshot", "", False)[0],
                "error": f"forensics module unavailable: {e}"}
    data = forensics_linux.collect(ioc_ips=params.get("ips") or [],
                                   ioc_commands=params.get("commands") or [])
    return {"ran": True, "dry_run": False, "read_only": True,
            "command": build_commands("snapshot", "", False)[0],
            "exit_code": 0, "forensics": data}


def run(action: dict, allow_armed: bool) -> dict:
    playbook = action.get("playbook", "")
    target = action.get("target", "")
    undo = bool(action.get("undo"))
    armed = action.get("mode") == "armed"

    if playbook == "snapshot" and not undo:
        return _snapshot(action)

    cmds = build_commands(playbook, target, undo)
    command = " && ".join(cmds)

    really = playbook in READ_ONLY or (armed and allow_armed)
    if not really:
        note = ("agent not armed (set PRAHARI_ALLOW_ARMED=true to execute)"
                if armed else "dry-run — operator approved without arming")
        return {"ran": False, "dry_run": True, "command": command, "note": note}

    if not cmds:
        return {"ran": False, "dry_run": False, "command": "", "note": "nothing to undo"}

    out: list[str] = []
    for c in cmds:
        p = subprocess.run(c, shell=True, capture_output=True, text=True)
        if p.stdout:
            out.append(p.stdout.strip())
        if p.returncode != 0:
            return {"ran": True, "dry_run": False, "command": command,
                    "stdout": "\n".join(out)[:2000], "exit_code": p.returncode,
                    "error": (p.stderr or "command failed").strip()[:300]}
    return {"ran": True, "dry_run": False, "command": command,
            "stdout": "\n".join(out)[:2000], "exit_code": 0}
