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
        return ["sh -c 'echo == processes ==; ps aux; echo; echo == connections ==; "
                "ss -tunap 2>/dev/null; echo; echo == sessions ==; who; last -n 20 2>/dev/null'"]
    return []


def run(action: dict, allow_armed: bool) -> dict:
    playbook = action.get("playbook", "")
    target = action.get("target", "")
    undo = bool(action.get("undo"))
    armed = action.get("mode") == "armed"
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
