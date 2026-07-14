from __future__ import annotations

import re

from prahari.schema import CanonicalEvent

DISCOVERY_COMMANDS = frozenset({
    "whoami", "ipconfig", "net", "nltest", "systeminfo",
    "tasklist", "arp", "quser", "netstat", "hostname", "wmic",
})

# token match, not substring — "systemd-hostnamed" must NOT read as "hostname"
_TOKEN_SPLIT = re.compile(r"[\s/\\;&|\"']+")


def _command_tokens(cmd: str) -> set[str]:
    return {t.removesuffix(".exe") for t in _TOKEN_SPLIT.split(cmd.lower()) if t}


def killchain_phase(event: CanonicalEvent) -> str:
    if event.event_type == "auth":
        return "lateral_movement"
    if event.event_type == "process":
        if _command_tokens(event.dest_entity or "") & DISCOVERY_COMMANDS:
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
