"""Targeted live forensics for Linux hosts. Stdlib only, no pip install.

The point of this module is the pivot that turns a network alert into a named
intruder: an incident tells us *an address* was contacted, and this answers
**which process owns that socket, where its binary lives, and who launched it**.

    /proc/net/tcp   remote addr → socket inode
    /proc/<pid>/fd  socket inode → pid          ← needs root for other users' pids
    /proc/<pid>/... pid → exe, cmdline, cwd, uid, parent chain

Everything is read-only. The mappers are pure so they can be unit-tested without
a live host; the collect_* functions touch /proc.

Root: without it the kernel hides other users' /proc/<pid>/fd, so sockets owned
by another account (usually the interesting ones) cannot be attributed. We do not
fail in that case — we degrade and say exactly what was unreadable.
"""
from __future__ import annotations

import hashlib
import os
import pwd
import socket
import struct
import time
from datetime import datetime, timezone

# TCP states as reported in /proc/net/tcp column 4
TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}
# a binary running from one of these is not normal for a service
SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")
# where persistence is usually planted
PERSISTENCE_PATHS = (
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron",
    "/etc/systemd/system", "/usr/lib/systemd/system", "/etc/rc.local",
)
PERSISTENCE_WINDOW_S = 24 * 3600
MAX_PARENTS = 6
HASH_MAX_BYTES = 64 * 1024 * 1024  # don't hash enormous binaries


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---- pure mappers (unit-testable) -------------------------------------------
def parse_hex_addr(field: str) -> tuple[str, int]:
    """'0100007F:1F90' → ('127.0.0.1', 8080). Kernel writes the address as
    little-endian hex words, so bytes come back reversed."""
    hex_ip, _, hex_port = field.partition(":")
    port = int(hex_port, 16) if hex_port else 0
    raw = bytes.fromhex(hex_ip)
    if len(raw) == 4:  # IPv4 — one LE word
        return socket.inet_ntop(socket.AF_INET, raw[::-1]), port
    if len(raw) == 16:  # IPv6 — four LE words, each reversed independently
        be = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        # ::ffff:a.b.c.d is a v4 socket on a v6 listener — report it as v4
        if be[:12] == b"\x00" * 10 + b"\xff\xff":
            return socket.inet_ntop(socket.AF_INET, be[12:]), port
        return socket.inet_ntop(socket.AF_INET6, be), port
    return field, port


def parse_proc_net(text: str) -> list[dict]:
    """Parse /proc/net/tcp or tcp6 into socket rows keyed by inode."""
    rows = []
    for line in text.splitlines()[1:]:  # skip header
        p = line.split()
        if len(p) < 10:
            continue
        try:
            lip, lport = parse_hex_addr(p[1])
            rip, rport = parse_hex_addr(p[2])
        except (ValueError, OSError):
            continue
        rows.append({
            "local_ip": lip, "local_port": lport,
            "remote_ip": rip, "remote_port": rport,
            "state": TCP_STATES.get(p[3].upper(), p[3]),
            "uid": p[7], "inode": p[9],
        })
    return rows


def classify_exe(exe: str | None) -> list[str]:
    """Flags derived purely from where the binary lives."""
    flags = []
    if not exe:
        return ["exe_unreadable"]
    if exe.endswith(" (deleted)"):
        # binary unlinked while still running — a hallmark of dropped malware
        flags.append("deleted_binary")
    path = exe[:-len(" (deleted)")] if exe.endswith(" (deleted)") else exe
    if path.startswith(SUSPICIOUS_DIRS):
        flags.append("suspicious_path")
    return flags


def score_connection(conn: dict, ioc_ips: set[str]) -> list[str]:
    """Why this connection is worth the analyst's attention."""
    flags = list(conn.get("flags", []))
    if conn.get("remote_ip") in ioc_ips:
        flags.append("incident_ioc")
    if conn.get("state") == "LISTEN" and conn.get("local_ip") not in ("127.0.0.1", "::1"):
        flags.append("listening")
    return flags


def rank(flags: list[str]) -> int:
    """Higher = show first. Keeps the UI ordering out of the renderer."""
    weight = {"incident_ioc": 100, "deleted_binary": 50, "suspicious_path": 30,
              "listening": 10, "exe_unreadable": 5}
    return sum(weight.get(f, 0) for f in flags)


# ---- /proc readers ----------------------------------------------------------
def _read(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            return f.read().decode(errors="replace")
    except OSError:
        return None


def _readlink(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def _user_of(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def process_info(pid: str) -> dict:
    """Everything we can learn about one pid. Missing fields stay None rather
    than raising — a process can exit mid-scan."""
    status = _read(f"/proc/{pid}/status") or ""
    ppid, uid = None, None
    for line in status.splitlines():
        if line.startswith("PPid:"):
            ppid = line.split()[1]
        elif line.startswith("Uid:"):
            uid = int(line.split()[1])  # effective uid
    cmdline = _read(f"/proc/{pid}/cmdline") or ""
    exe = _readlink(f"/proc/{pid}/exe")
    info = {
        "pid": pid, "ppid": ppid,
        "user": _user_of(uid) if uid is not None else None,
        "exe": exe,
        "cmdline": cmdline.replace("\x00", " ").strip(),
        "cwd": _readlink(f"/proc/{pid}/cwd"),
        "started": _start_time(pid),
    }
    info["flags"] = classify_exe(exe)
    return info


def _start_time(pid: str) -> str | None:
    try:
        return datetime.fromtimestamp(os.stat(f"/proc/{pid}").st_ctime,
                                      timezone.utc).isoformat()
    except OSError:
        return None


def parent_chain(pid: str, max_depth: int = MAX_PARENTS) -> list[dict]:
    """Walk PPid upward — this is 'how did they get in'. sshd at the top of a
    chain ending in a shell is a very different story from a systemd service."""
    chain, seen, cur = [], set(), pid
    for _ in range(max_depth):
        info = process_info(cur)
        ppid = info.get("ppid")
        if not ppid or ppid in seen or ppid == "0":
            break
        seen.add(ppid)
        parent = process_info(ppid)
        if not parent.get("cmdline") and not parent.get("exe"):
            break
        chain.append({"pid": ppid, "exe": parent["exe"],
                      "cmdline": parent["cmdline"], "user": parent["user"]})
        cur = ppid
    return chain


def sha256_of(path: str | None) -> str | None:
    """Hash the on-disk binary so one host's finding becomes a fleet-wide IOC."""
    if not path or path.endswith(" (deleted)"):
        return None
    try:
        if os.path.getsize(path) > HASH_MAX_BYTES:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def socket_inode_map() -> tuple[dict[str, str], list[str]]:
    """socket inode → owning pid, by walking every /proc/<pid>/fd.

    Returns the map plus the pids we were not allowed to read (the reason root
    matters: without it this is only our own processes)."""
    mapping: dict[str, str] = {}
    denied: list[str] = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            denied.append(pid)
            continue
        except OSError:
            continue  # process exited
        for fd in fds:
            link = _readlink(f"{fd_dir}/{fd}")
            if link and link.startswith("socket:["):
                mapping[link[8:-1]] = pid
    return mapping, denied


def collect_persistence(window_s: int = PERSISTENCE_WINDOW_S) -> list[dict]:
    """Recently-touched autostart locations + authorized_keys. Persistence is
    what survives a reboot, so it is what containment must not miss."""
    cutoff = time.time() - window_s
    out = []

    def note(path: str, kind: str) -> None:
        try:
            st = os.stat(path)
        except OSError:
            return
        if st.st_mtime >= cutoff:
            out.append({"path": path, "kind": kind,
                        "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()})

    for base in PERSISTENCE_PATHS:
        if os.path.isfile(base):
            note(base, "startup")
        elif os.path.isdir(base):
            try:
                for name in os.listdir(base):
                    note(os.path.join(base, name), "startup")
            except OSError:
                continue
    try:
        for entry in pwd.getpwall():
            if entry.pw_dir and os.path.isdir(entry.pw_dir):
                note(os.path.join(entry.pw_dir, ".ssh", "authorized_keys"), "ssh_key")
    except OSError:
        pass
    return sorted(out, key=lambda d: d["modified"], reverse=True)[:20]


# ---- the collector ----------------------------------------------------------
def collect(ioc_ips: list[str] | None = None, ioc_commands: list[str] | None = None,
            limit: int = 40) -> dict:
    """Targeted snapshot. `ioc_ips` are the incident's C2 addresses — connections
    to them are surfaced first and flagged `incident_ioc`."""
    ips = set(ioc_ips or [])
    cmds = [c for c in (ioc_commands or []) if c]
    is_root = os.geteuid() == 0

    raw = (_read("/proc/net/tcp") or "") + "\n" + (_read("/proc/net/tcp6") or "")
    sockets = parse_proc_net(raw)
    inode_pid, denied = socket_inode_map()

    conns, pid_cache = [], {}
    for s in sockets:
        if s["state"] not in ("ESTABLISHED", "LISTEN", "SYN_SENT", "CLOSE_WAIT"):
            continue
        pid = inode_pid.get(s["inode"])
        info = {}
        if pid:
            if pid not in pid_cache:
                pid_cache[pid] = process_info(pid)
            info = pid_cache[pid]
        c = {**s, **{k: v for k, v in info.items() if k != "flags"},
             "flags": list(info.get("flags", []))}
        c["flags"] = score_connection(c, ips)
        c["rank"] = rank(c["flags"])
        conns.append(c)

    # a listener's remote is always 0.0.0.0:0 — show what it's bound to instead
    for c in conns:
        listen = c["state"] == "LISTEN"
        c["addr"] = (f"{c['local_ip']}:{c['local_port']}" if listen
                     else f"{c['remote_ip']}:{c['remote_port']}")

    # one row per (pid, address, state) — a process holding several sockets to the
    # same peer is one fact, not five
    unique: dict[tuple, dict] = {}
    for c in conns:
        key = (c.get("pid"), c["addr"], c["state"])
        if key not in unique or c["rank"] > unique[key]["rank"]:
            unique[key] = c
    conns = list(unique.values())

    # loopback chatter is only worth showing when it is actually implicated
    conns = [c for c in conns
             if c["rank"] > 0 and (c["remote_ip"] not in ("127.0.0.1", "::1")
                                   or "incident_ioc" in c["flags"])]
    conns.sort(key=lambda c: (-c["rank"], c.get("addr") or ""))
    conns = conns[:limit]

    # enrich only what we are going to show — hashing is the expensive part
    for c in conns:
        if c.get("pid") and c["rank"] >= rank(["suspicious_path"]):
            c["parents"] = parent_chain(c["pid"])
            c["sha256"] = sha256_of(c.get("exe"))

    # processes matching an incident command, even with no live socket
    matched_procs = []
    if cmds:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            info = pid_cache.get(pid) or process_info(pid)
            cl = info.get("cmdline") or ""
            if cl and any(c in cl for c in cmds):
                info["parents"] = parent_chain(pid)
                info["sha256"] = sha256_of(info.get("exe"))
                matched_procs.append(info)

    findings = build_findings(conns, matched_procs)
    degraded = []
    if not is_root:
        degraded.append(
            f"not running as root — {len(denied)} processes' sockets could not be "
            "attributed to a pid (other users' /proc/<pid>/fd is unreadable)")

    return {
        "collected_at": _now(),
        "root": is_root,
        "ioc_ips": sorted(ips),
        "connections": conns,
        "processes": matched_procs,
        "persistence": collect_persistence(),
        "findings": findings,
        "counts": {"sockets": len(sockets), "shown": len(conns),
                   "ioc_matches": sum(1 for c in conns if "incident_ioc" in c["flags"])},
        "degraded": degraded,
    }


def build_findings(conns: list[dict], procs: list[dict]) -> list[dict]:
    """Turn raw rows into the handful of sentences an analyst actually reads.
    One finding per distinct fact — the same pid on five sockets is one story."""
    out: list[dict] = []
    seen: set[tuple] = set()

    def emit(key: tuple, **finding) -> None:
        if key not in seen:
            seen.add(key)
            out.append(finding)

    for c in conns:
        addr = c.get("addr") or c.get("remote_ip")
        if "incident_ioc" in c["flags"]:
            who = c.get("exe") or c.get("cmdline") or "unattributed"
            if not c.get("pid"):
                emit(("orphan", addr), severity="warn",
                     title=f"Connection to {addr} is live but its owner is unknown",
                     detail="The socket is open and no pid could be attributed to it. Run the "
                            "collector as root to resolve the owning process.")
            else:
                emit(("owner", c["pid"], addr), severity="critical",
                     title=f"PID {c['pid']} {who} owns the connection to {addr}",
                     detail=f"user {c.get('user')} · {c['state']}"
                            + (f" · launched by {c['parents'][0]['cmdline'][:120]}"
                               if c.get("parents") else ""),
                     pid=c["pid"], sha256=c.get("sha256"))
        if "deleted_binary" in c["flags"]:
            emit(("deleted", c.get("pid")), severity="critical",
                 title=f"PID {c.get('pid')} is running a binary that was deleted from disk",
                 detail=f"{c.get('exe')} — unlinking the executable while it runs is a standard "
                        "anti-forensics move. Capture /proc/<pid>/exe before killing it.",
                 pid=c.get("pid"))
        elif "suspicious_path" in c["flags"]:
            emit(("suspath", c.get("pid")), severity="warn",
                 title=f"PID {c.get('pid')} runs from a world-writable directory",
                 detail=f"{c.get('exe')} — services do not normally live here.",
                 pid=c.get("pid"))
    for p in procs:
        emit(("proc", p["pid"]), severity="warn",
             title=f"PID {p['pid']} matches a command seen in this incident",
             detail=(p.get("cmdline") or "")[:300], pid=p["pid"], sha256=p.get("sha256"))

    order = {"critical": 0, "warn": 1}
    out.sort(key=lambda f: order.get(f["severity"], 2))
    return out
