from __future__ import annotations

from collections.abc import Iterator
from datetime import timezone
from pathlib import Path

import pandas as pd

from prahari.schema import CanonicalEvent


def _to_int(value) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _to_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_cicids_row(row: dict) -> CanonicalEvent:
    label = str(row.get("Label", "BENIGN")).strip()
    labels = [] if label.upper() == "BENIGN" else ["attack", label]
    ts = pd.to_datetime(row["Timestamp"]).to_pydatetime()
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return CanonicalEvent(
        timestamp=ts,
        event_type="network_flow",
        src_ip=(str(row["Source IP"]) if row.get("Source IP") is not None else None),
        dst_ip=(str(row["Destination IP"]) if row.get("Destination IP") is not None else None),
        action="connect",
        bytes=_to_int(row.get("Total Length of Fwd Packets")),
        duration=_to_float(row.get("Flow Duration")),
        source="cicids",
        labels=labels,
        raw=",".join(str(v) for v in row.values()),
    )


def parse_cicids_file(path: str | Path) -> Iterator[CanonicalEvent]:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    for record in df.to_dict(orient="records"):
        yield parse_cicids_row(record)
