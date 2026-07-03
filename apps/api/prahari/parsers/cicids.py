from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from prahari.schema import CanonicalEvent

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


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


def _labels(label: str) -> list[str]:
    label = str(label).strip()
    return [] if label.upper() == "BENIGN" else ["attack", label]


def _timestamp(row: dict) -> datetime:
    if "Timestamp" in row and row.get("Timestamp") is not None:
        ts = pd.to_datetime(row["Timestamp"]).to_pydatetime()
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return _EPOCH


def parse_cicids_row(row: dict) -> CanonicalEvent:
    return CanonicalEvent(
        timestamp=_timestamp(row),
        event_type="network_flow",
        src_ip=(str(row["Source IP"]) if row.get("Source IP") is not None else None),
        dst_ip=(str(row["Destination IP"]) if row.get("Destination IP") is not None else None),
        action="connect",
        bytes=_to_int(row.get("Total Length of Fwd Packets")),
        duration=_to_float(row.get("Flow Duration")),
        source="cicids",
        labels=_labels(row.get("Label", "BENIGN")),
        raw=",".join(str(v) for v in row.values()),
    )


def parse_cicids_file(path: str | Path) -> Iterator[CanonicalEvent]:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    for record in df.to_dict(orient="records"):
        yield parse_cicids_row(record)


# MachineLearningCVE variant: flow features + Label only (no IP/Timestamp).
def parse_cicids_ml_row(row: dict) -> CanonicalEvent:
    return CanonicalEvent(
        timestamp=_EPOCH,
        event_type="network_flow",
        action="connect",
        bytes=_to_int(row.get("Total Length of Fwd Packets")),
        duration=_to_float(row.get("Flow Duration")),
        source="cicids",
        labels=_labels(row.get("Label", "BENIGN")),
        raw=",".join(str(v) for v in row.values()),
    )


def parse_cicids_ml_file(path: str | Path) -> Iterator[CanonicalEvent]:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    for record in df.to_dict(orient="records"):
        yield parse_cicids_ml_row(record)
