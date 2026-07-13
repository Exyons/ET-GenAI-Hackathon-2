"""Linux telemetry → CanonicalEvent-shaped dicts. Stdlib only (runs on the VM with
no pip install). The mappers are pure/testable; the *_tail generators wrap subprocess.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
from collections.abc import Iterator
from datetime import datetime, timezone

HOSTNAME = socket.gethostname()

_INTERNAL = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
             "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
             "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.")


def is_internal(ip: str | None) -> bool | None:
    if not ip:
        return None
    return ip.startswith(_INTERNAL)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---- auth (sshd via journalctl / auth.log) ----
_ACCEPT = re.compile(r"Accepted (\w+) for (?:invalid user )?(\S+) from (\S+)")
_FAIL = re.compile(r"Failed (\w+) for (?:invalid user )?(\S+) from (\S+)")


def map_auth(msg: str, ts: str, hostname: str = HOSTNAME) -> dict | None:
    for rx, outcome in ((_ACCEPT, "success"), (_FAIL, "failure")):
        m = rx.search(msg)
        if m:
            method, user, ip = m.groups()
            return {"timestamp": ts, "event_type": "auth", "source": "linux-auth",
                    "source_entity": user, "src_host": hostname, "dst_host": hostname,
                    "src_ip": ip, "outcome": outcome, "auth_type": method, "raw": msg}
    return None


# ---- process (auditd execve) ----
def _field(line: str, key: str) -> str | None:
    m = re.search(rf'{key}="([^"]*)"', line) or re.search(rf'\b{key}=(\S+)', line)
    return m.group(1) if m else None


def map_audit_execve(line: str, ts: str, hostname: str = HOSTNAME) -> dict | None:
    if "execve" not in line and "EXECVE" not in line:
        return None
    cmd = _field(line, "exe") or _field(line, "comm")
    if not cmd:
        return None
    return {"timestamp": ts, "event_type": "process", "source": "linux-audit",
            "source_entity": _field(line, "AUID") or _field(line, "auid"),
            "src_host": hostname, "dest_entity": cmd, "raw": line.strip()}


# ---- network (conntrack NEW events) ----
def map_conntrack(line: str, ts: str, hostname: str = HOSTNAME) -> dict | None:
    if "[NEW]" not in line:
        return None
    m = re.search(r"\bdst=(\S+)", line)
    if not m:
        return None
    src = re.search(r"\bsrc=(\S+)", line)
    return {"timestamp": ts, "event_type": "network_flow", "source": "linux-conntrack",
            "src_host": hostname, "dst_ip": m.group(1),
            "src_internal": is_internal(src.group(1)) if src else None, "raw": line.strip()}


# ---- live tailers (wrap subprocess; not unit-tested) ----
def _lines(cmd: list[str]) -> Iterator[str]:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line.rstrip("\n")


def tail_auth() -> Iterator[dict]:
    for line in _lines(["journalctl", "-f", "-o", "json", "-n", "0", "-u", "ssh", "-u", "sshd"]):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        d = map_auth(rec.get("MESSAGE", ""), _now(), rec.get("_HOSTNAME", HOSTNAME))
        if d:
            yield d


def tail_process() -> Iterator[dict]:
    for line in _lines(["journalctl", "-f", "-o", "cat", "-n", "0", "_TRANSPORT=audit"]):
        d = map_audit_execve(line, _now())
        if d:
            yield d


def tail_network() -> Iterator[dict]:
    for line in _lines(["conntrack", "-E", "-e", "NEW", "-p", "tcp"]):
        d = map_conntrack(line, _now())
        if d:
            yield d
