"""Windows telemetry → CanonicalEvent-shaped dicts. Stdlib only (runs on the
monitored box with any stock Python). Pure mappers parse event XML (from
EventLogRecord.ToXml()); the *_tail generators poll Get-WinEvent via PowerShell.

Sources:
- auth    — Security 4624/4625 (logon success/failure)
- process — Sysmon EventID 1 (process create), Security 4688 fallback
- network — Sysmon EventID 3 (network connection)
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import time
from collections.abc import Iterator
from datetime import datetime, timezone

HOSTNAME = socket.gethostname()
POLL_SECONDS = 3.0

_INTERNAL = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
             "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
             "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.")

_SERVICE_ACCOUNTS = {"", "-", "system", "local service", "network service", "anonymous logon"}


def is_internal(ip: str | None) -> bool | None:
    if not ip:
        return None
    return ip.startswith(_INTERNAL)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _data(xml: str, name: str) -> str | None:
    m = re.search(rf"<Data Name=['\"]{name}['\"]>([^<]*)</Data>", xml)
    return m.group(1) if m else None


def _event_id(xml: str) -> int | None:
    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
    return int(m.group(1)) if m else None


def _is_noise_account(user: str | None) -> bool:
    return user is None or user.endswith("$") or user.lower() in _SERVICE_ACCOUNTS


# ---- auth (Security 4624 success / 4625 failure) ----
def map_security_auth(xml: str, ts: str, hostname: str = HOSTNAME) -> dict | None:
    eid = _event_id(xml)
    if eid not in (4624, 4625):
        return None
    user = _data(xml, "TargetUserName")
    if _is_noise_account(user):
        return None
    ip = _data(xml, "IpAddress")
    ip = None if ip in (None, "-", "::1", "127.0.0.1") else ip
    return {"timestamp": ts, "event_type": "auth", "source": "windows-security",
            "source_entity": user, "src_host": hostname, "dst_host": hostname,
            "src_ip": ip, "outcome": "success" if eid == 4624 else "failure",
            "auth_type": _data(xml, "AuthenticationPackageName") or _data(xml, "LogonType"),
            "raw": xml}


# ---- process (Sysmon 1; Security 4688 fallback) ----
def map_process(xml: str, ts: str, hostname: str = HOSTNAME) -> dict | None:
    eid = _event_id(xml)
    if eid == 1:  # Sysmon process create
        cmd = _data(xml, "CommandLine") or _data(xml, "Image")
        source, user = "windows-sysmon", _data(xml, "User")
    elif eid == 4688:  # Security process creation
        cmd = _data(xml, "CommandLine") or _data(xml, "NewProcessName")
        source, user = "windows-security", _data(xml, "SubjectUserName")
    else:
        return None
    if not cmd or (user and user.endswith("$")):
        return None
    return {"timestamp": ts, "event_type": "process", "source": source,
            "source_entity": user, "src_host": hostname, "dest_entity": cmd, "raw": xml}


# ---- network (Sysmon 3 connection detected) ----
def map_sysmon_network(xml: str, ts: str, hostname: str = HOSTNAME) -> dict | None:
    if _event_id(xml) != 3:
        return None
    dst = _data(xml, "DestinationIp")
    if not dst:
        return None
    return {"timestamp": ts, "event_type": "network_flow", "source": "windows-sysmon",
            "src_host": hostname, "dst_ip": dst,
            "src_internal": is_internal(_data(xml, "SourceIp")), "raw": xml}


# ---- live tailers (poll Get-WinEvent; not unit-tested) ----
_PS = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"


def _query(log: str, event_ids: list[int], cursor: int) -> list[dict]:
    """Return [{'r': RecordId, 'x': xml}, ...] newer than cursor, oldest first."""
    conds = " or ".join(f"EventID={i}" for i in event_ids)
    script = (
        f"$ev = @(Get-WinEvent -LogName '{log}' -FilterXPath '*[System[{conds}]]' "
        f"-MaxEvents 300 -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.RecordId -gt {cursor} }} | Sort-Object RecordId | "
        f"Select-Object @{{n='r';e={{$_.RecordId}}}}, @{{n='x';e={{$_.ToXml()}}}}); "
        f"ConvertTo-Json -InputObject $ev -Compress"
    )
    out = subprocess.run(_PS + [script], capture_output=True, text=True, timeout=60).stdout.strip()
    if not out:
        return []
    parsed = json.loads(out)
    return parsed if isinstance(parsed, list) else [parsed]


def _tail(log: str, event_ids: list[int], mapper) -> Iterator[dict]:
    cursor = 0
    first = True
    while True:
        records = _query(log, event_ids, cursor)
        for rec in records:
            cursor = max(cursor, int(rec["r"]))
            if first:
                continue  # skip history; ship only events after startup
            d = mapper(rec["x"], _now())
            if d:
                yield d
        first = False
        time.sleep(POLL_SECONDS)


def _sysmon_available() -> bool:
    script = f"if (Get-WinEvent -ListLog '{SYSMON_LOG}' -ErrorAction SilentlyContinue) {{ 'yes' }}"
    out = subprocess.run(_PS + [script], capture_output=True, text=True, timeout=60).stdout
    return "yes" in out


def tail_auth() -> Iterator[dict]:
    yield from _tail("Security", [4624, 4625], map_security_auth)


def tail_process() -> Iterator[dict]:
    # Sysmon if installed, else Security 4688 (needs process-creation auditing)
    if _sysmon_available():
        yield from _tail(SYSMON_LOG, [1], map_process)
    else:
        yield from _tail("Security", [4688], map_process)


def tail_network() -> Iterator[dict]:
    yield from _tail(SYSMON_LOG, [3], map_sysmon_network)
