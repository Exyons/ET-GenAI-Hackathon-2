from __future__ import annotations

from prahari.correlate.correlator import correlate
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import target_of
from prahari.enrich import enrich
from prahari.parsers.lanl import (
    parse_lanl_flow_line, parse_lanl_line, parse_lanl_proc_line,
)


def build_incidents(
    auth_lines: list[str],
    proc_lines: list[str],
    flow_lines: list[str],
    redteam: set[tuple[str, str, str, str]],
    window_seconds: float = 600,
) -> list[Incident]:
    events = [parse_lanl_line(ln, redteam) for ln in auth_lines if ln.strip()]
    for ln in proc_lines:
        if ln.strip():
            ev = parse_lanl_proc_line(ln)
            if ev is not None:
                events.append(ev)
    events += [parse_lanl_flow_line(ln) for ln in flow_lines if ln.strip()]

    events = [enrich(e) for e in events]
    return correlate(events, key_fn=target_of, window_seconds=window_seconds)
