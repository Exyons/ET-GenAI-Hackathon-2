"""Linux telemetry → CanonicalEvent-shaped dicts. Stdlib only (runs on the VM with
no pip install). The mappers are pure/testable; the *_tail generators wrap subprocess.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import socket
import subprocess
import time
from collections.abc import Iterator
from datetime import datetime, timezone

HOSTNAME = socket.gethostname()
OS_NAME = "linux"
SOURCE_IDS = {"auth": "linux-auth", "process": "linux-audit", "network": "linux-conntrack"}

_INTERNAL = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
             "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
             "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.")


def is_internal(ip: str | None) -> bool | None:
    if not ip:
        return None
    ip = ip.lower()
    if ":" in ip:  # IPv6: loopback, link-local, unique-local are internal
        return ip == "::1" or ip.startswith(("fe80:", "fd", "fc"))
    return ip.startswith(_INTERNAL)


def is_loopback(ip: str | None) -> bool:
    return ip is not None and (ip.startswith("127.") or ip == "::1")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---- auth (sshd + sudo via journalctl) ----
_ACCEPT = re.compile(r"Accepted (\w+) for (?:invalid user )?(\S+) from (\S+)")
_FAIL = re.compile(r"Failed (\w+) for (?:invalid user )?(\S+) from (\S+)")
_SUDO_FAIL = re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*\buser=(\S+)")
_SUDO_CMD = re.compile(r"^\s*(\S+) : .*\bCOMMAND=(.+)$")


def map_auth(msg: str, ts: str, hostname: str = HOSTNAME) -> dict | None:
    for rx, outcome in ((_ACCEPT, "success"), (_FAIL, "failure")):
        m = rx.search(msg)
        if m:
            method, user, ip = m.groups()
            return {"timestamp": ts, "event_type": "auth", "source": "linux-auth",
                    "source_entity": user, "src_host": hostname, "dst_host": hostname,
                    "src_ip": ip, "outcome": outcome, "auth_type": method, "raw": msg}
    return None


def map_sudo(msg: str, ts: str, hostname: str = HOSTNAME) -> dict | None:
    m = _SUDO_FAIL.search(msg)
    if m:
        return {"timestamp": ts, "event_type": "auth", "source": "linux-auth",
                "source_entity": m.group(1), "src_host": hostname, "dst_host": hostname,
                "outcome": "failure", "auth_type": "sudo", "raw": msg}
    m = _SUDO_CMD.match(msg)
    if m:  # privileged exec — a desktop's most telling process telemetry
        user, cmd = m.groups()
        return {"timestamp": ts, "event_type": "process", "source": "linux-sudo",
                "source_entity": user, "src_host": hostname,
                "dest_entity": cmd.strip(), "raw": msg}
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
    if is_loopback(m.group(1)):
        return None  # localhost chatter is not network telemetry
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
    # sshd logins + sudo (auth failures and privileged COMMAND= execs)
    cmd = ["journalctl", "-f", "-o", "json", "-n", "0",
           "-u", "ssh", "-u", "sshd", "+", "_COMM=sudo"]
    for line in _lines(cmd):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        msg = rec.get("MESSAGE", "")
        host = rec.get("_HOSTNAME", HOSTNAME)
        d = map_auth(msg, _now(), host) or map_sudo(msg, _now(), host)
        if d:
            yield d


def map_proc(pid: str, cmdline: str, user: str, ts: str, hostname: str = HOSTNAME) -> dict:
    return {"timestamp": ts, "event_type": "process", "source": "linux-proc",
            "source_entity": user, "src_host": hostname, "dest_entity": cmdline,
            "raw": f"pid={pid} {cmdline}"}


def _proc_user(pid: str) -> str:
    try:
        return pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
    except (OSError, KeyError):
        return "?"


PROC_DEDUP_SECONDS = float(os.environ.get("PRAHARI_PROC_DEDUP_SECONDS", "60"))
_DIGITS = re.compile(r"\d+")


def proc_signature(user: str, cmd: str) -> str:
    # collapse numeric args so a polling loop (cpuUsage.sh <pid>, sleep 1, …)
    # shares one signature regardless of the changing pid
    return f"{user}|{_DIGITS.sub('#', cmd)}"


class _Deduper:
    """Suppress a repeated signature within a TTL. A genuinely new command, or the
    same one after the window, still passes — this only silences tight repeats."""

    def __init__(self, ttl: float) -> None:
        self.ttl = ttl
        self._seen: dict[str, float] = {}

    def fresh(self, sig: str, now: float) -> bool:
        # stores the last time we EMITTED — a command repeating every second still
        # surfaces once per TTL (a heartbeat), rather than vanishing from the tape
        last = self._seen.get(sig)
        if last is not None and now - last < self.ttl:
            return False
        if len(self._seen) > 4096:  # bound memory on churny hosts
            self._seen = {k: t for k, t in self._seen.items() if now - t < self.ttl}
        self._seen[sig] = now
        return True


def _scan_proc(poll: float = 0.5, dedup_seconds: float = PROC_DEDUP_SECONDS) -> Iterator[dict]:
    """No auditd → poll /proc for new processes. Zero setup; misses very
    short-lived commands but catches normal desktop/server activity. Tight repeats
    of the same command (polling loops, editor CPU probes) are deduped so they
    don't flood the tape."""
    prev = {p for p in os.listdir("/proc") if p.isdigit()}
    dedup = _Deduper(dedup_seconds)
    while True:
        time.sleep(poll)
        now = time.monotonic()
        cur = {p for p in os.listdir("/proc") if p.isdigit()}
        for pid in sorted(cur - prev, key=int):
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
            except OSError:
                continue  # process already gone
            if not cmd:
                continue
            user = _proc_user(pid)
            if dedup.fresh(proc_signature(user, cmd), now):
                yield map_proc(pid, cmd, user, _now())
        prev = cur


def _audit_available() -> bool:
    try:
        out = subprocess.run(["journalctl", "-o", "cat", "-n", "1", "_TRANSPORT=audit"],
                             capture_output=True, text=True, timeout=10)
        return bool(out.stdout.strip())
    except Exception:
        return False


def tail_process() -> Iterator[dict]:
    if _audit_available():
        for line in _lines(["journalctl", "-f", "-o", "cat", "-n", "0", "_TRANSPORT=audit"]):
            d = map_audit_execve(line, _now())
            if d:
                yield d
    else:
        yield from _scan_proc()


def tail_network() -> Iterator[dict]:
    for line in _lines(["conntrack", "-E", "-e", "NEW", "-p", "tcp"]):
        d = map_conntrack(line, _now())
        if d:
            yield d
