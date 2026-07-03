from __future__ import annotations

from pathlib import Path

from prahari.enrich import enrich
from prahari.parsers.cicids import parse_cicids_file
from prahari.parsers.lanl import parse_lanl_file
from prahari.parsers.process import parse_sysmon_file
from prahari.schema import CanonicalEvent
from prahari.stream import merge_ordered


def load_all(
    lanl_auth: str | Path | None = None,
    lanl_redteam: str | Path | None = None,
    cicids: str | Path | None = None,
    sysmon: str | Path | None = None,
) -> list[CanonicalEvent]:
    streams: list[list[CanonicalEvent]] = []
    if lanl_auth is not None and lanl_redteam is not None:
        streams.append(list(parse_lanl_file(lanl_auth, lanl_redteam)))
    if cicids is not None:
        streams.append(list(parse_cicids_file(cicids)))
    if sysmon is not None:
        streams.append(list(parse_sysmon_file(sysmon)))

    merged = merge_ordered(*streams)
    return [enrich(ev) for ev in merged]
