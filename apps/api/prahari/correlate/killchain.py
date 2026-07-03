from __future__ import annotations

from prahari.schema import CanonicalEvent

DISCOVERY_COMMANDS = (
    "whoami", "ipconfig", "net ", "net.exe", "nltest", "systeminfo",
    "tasklist", "arp", "quser", "netstat", "hostname", "wmic",
)


def killchain_phase(event: CanonicalEvent) -> str:
    if event.event_type == "auth":
        return "lateral_movement"
    if event.event_type == "process":
        cmd = (event.dest_entity or "").lower()
        if any(k in cmd for k in DISCOVERY_COMMANDS):
            return "discovery"
        return "execution"
    if event.event_type == "network_flow":
        return "command_and_control"
    return "unknown"


def actor_of(event: CanonicalEvent) -> str | None:
    return event.source_entity


def target_of(event: CanonicalEvent) -> str | None:
    if event.event_type == "auth":
        return event.dst_host
    return event.src_host
