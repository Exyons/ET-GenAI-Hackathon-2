"""Response playbooks for Windows hosts. Stdlib only. Dry-run builds the exact
command(s); armed actually runs them. Mirrors responder_linux's run() contract.

Safety: really executes only when armed AND PRAHARI_ALLOW_ARMED=true; read-only
playbooks (snapshot) always run.
"""
from __future__ import annotations

import subprocess

READ_ONLY = {"snapshot"}
RULE = "PRAHARI-isolate"


def build_commands(playbook: str, target: str, undo: bool) -> list[str]:
    t = target.replace('"', "")
    if playbook == "isolate_host":
        if undo:
            return [f'netsh advfirewall firewall delete rule name="{RULE}"']
        return [
            f'netsh advfirewall firewall add rule name="{RULE}" dir=out '
            f'action=block remoteport=any protocol=tcp remoteip=any',
        ]
    if playbook == "block_ip":
        name = f"PRAHARI-block-{t}"
        if undo:
            return [f'netsh advfirewall firewall delete rule name="{name}"']
        return [f'netsh advfirewall firewall add rule name="{name}" dir=out '
                f'action=block remoteip={t}']
    if playbook == "disable_account":
        return [f'net user "{t}" /active:yes'] if undo else [f'net user "{t}" /active:no']
    if playbook == "kill_process":
        return [] if undo else [f'taskkill /IM "{t}" /F']
    if playbook == "snapshot":
        return ['powershell -NoProfile -Command '
                '"Get-Process | Select-Object -First 40; '
                'Get-NetTCPConnection -State Established -EA SilentlyContinue | '
                'Select-Object -First 40; quser 2>$null"']
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
