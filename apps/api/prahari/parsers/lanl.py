from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from prahari.schema import CanonicalEvent

# LANL times are integer seconds relative to the capture start.
# Anchor to an arbitrary UTC epoch so downstream code gets real datetimes.
LANL_EPOCH = datetime(2017, 1, 1, tzinfo=timezone.utc)

RedteamKey = tuple[str, str, str, str]


def load_redteam(path: str | Path) -> set[RedteamKey]:
    keys: set[RedteamKey] = set()
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        t, user, src, dst = line.split(",")
        keys.add((t, user, src, dst))
    return keys


def parse_lanl_line(line: str, redteam: set[RedteamKey]) -> CanonicalEvent:
    t, su, du, sc, dc, atype, ltype, orient, success = line.split(",")
    key: RedteamKey = (t, su, sc, dc)
    labels = ["redteam"] if key in redteam else []
    ts = LANL_EPOCH + timedelta(seconds=int(t))
    return CanonicalEvent(
        timestamp=ts,
        event_type="auth",
        source_entity=su,
        dest_entity=du,
        src_host=sc,
        dst_host=dc,
        action="login",
        outcome=success.lower(),
        auth_type=atype,
        source="lanl",
        labels=labels,
        raw=line,
    )


def parse_lanl_file(
    auth_path: str | Path, redteam_path: str | Path
) -> Iterator[CanonicalEvent]:
    redteam = load_redteam(redteam_path)
    for line in Path(auth_path).read_text().splitlines():
        if line.strip():
            yield parse_lanl_line(line, redteam)


def parse_lanl_proc_line(line: str) -> CanonicalEvent | None:
    t, user, computer, process, action = line.split(",")
    if action.strip() != "Start":
        return None
    return CanonicalEvent(
        timestamp=LANL_EPOCH + timedelta(seconds=int(t)),
        event_type="process",
        source_entity=user,
        src_host=computer,
        action="execute",
        dest_entity=process,
        source="lanl_proc",
        raw=line,
    )


def parse_lanl_proc_file(path: str | Path) -> Iterator[CanonicalEvent]:
    for line in Path(path).read_text().splitlines():
        if line.strip():
            ev = parse_lanl_proc_line(line)
            if ev is not None:
                yield ev


def parse_lanl_flow_line(line: str) -> CanonicalEvent:
    t, dur, sc, _sp, dc, _dp, _proto, _pkts, byts = line.split(",")
    return CanonicalEvent(
        timestamp=LANL_EPOCH + timedelta(seconds=int(t)),
        event_type="network_flow",
        src_host=sc,
        dst_host=dc,
        action="connect",
        bytes=int(byts),
        duration=float(dur),
        source="lanl_flow",
        raw=line,
    )


def parse_lanl_flow_file(path: str | Path) -> Iterator[CanonicalEvent]:
    for line in Path(path).read_text().splitlines():
        if line.strip():
            yield parse_lanl_flow_line(line)
