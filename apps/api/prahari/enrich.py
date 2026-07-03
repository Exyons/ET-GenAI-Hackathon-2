from __future__ import annotations

from prahari.schema import CanonicalEvent, Criticality

# Demo asset criticality table. In production this is a CMDB lookup.
ASSET_CRITICALITY: dict[str, Criticality] = {
    "C553": "critical",
    "C1115": "medium",
    "C988": "low",
}

_INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.")


def is_internal(ip: str | None) -> bool | None:
    if ip is None:
        return None
    return ip.startswith(_INTERNAL_PREFIXES)


def enrich(ev: CanonicalEvent) -> CanonicalEvent:
    host = ev.dst_host or ev.src_host
    if host and host in ASSET_CRITICALITY:
        ev.asset_criticality = ASSET_CRITICALITY[host]
    if ev.src_ip is not None:
        ev.src_internal = is_internal(ev.src_ip)
    return ev
