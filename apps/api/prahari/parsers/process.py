from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
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
