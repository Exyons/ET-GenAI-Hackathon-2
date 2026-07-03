from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from prahari.schema import CanonicalEvent


def parse_sysmon_obj(obj: dict) -> CanonicalEvent:
    ts = datetime.fromisoformat(obj["UtcTime"])
    return CanonicalEvent(
        timestamp=ts,
        event_type="process",
        source_entity=obj.get("User"),
        dest_entity=obj.get("CommandLine") or obj.get("Image"),
        src_host=obj.get("Computer"),
        action="execute",
        outcome="success",
        source="sysmon",
        labels=list(obj.get("_labels", [])),
        raw=json.dumps(obj, sort_keys=True),
    )


def parse_sysmon_file(path: str | Path) -> Iterator[CanonicalEvent]:
    for line in Path(path).read_text().splitlines():
        if line.strip():
            yield parse_sysmon_obj(json.loads(line))


def _otrf_timestamp(obj: dict) -> datetime:
    ts_raw = obj.get("@timestamp")
    if ts_raw:
        return datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    utc = obj["UtcTime"]  # "2021-06-12 01:07:15.633" (naive) -> treat as UTC
    return datetime.fromisoformat(utc).replace(tzinfo=timezone.utc)


def parse_otrf_obj(obj: dict, labels: list[str] | None = None) -> CanonicalEvent | None:
    if str(obj.get("EventID")) != "1":
        return None
    return CanonicalEvent(
        timestamp=_otrf_timestamp(obj),
        event_type="process",
        source_entity=obj.get("User"),
        dest_entity=obj.get("CommandLine") or obj.get("Image"),
        src_host=obj.get("Hostname"),
        action="execute",
        outcome="success",
        source="otrf",
        labels=list(labels or []),
        raw=json.dumps(obj, sort_keys=True),
    )


def parse_otrf_lines(
    lines: Iterable[str], labels: list[str] | None = None
) -> Iterator[CanonicalEvent]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        ev = parse_otrf_obj(json.loads(line), labels=labels)
        if ev is not None:
            yield ev
