from __future__ import annotations

from prahari.correlate.incident import Incident

# Playbook catalog. Command implementations live on the agent (OS-specific);
# the API only stores the recommendation. reversible playbooks can be undone.
CATALOG = {
    "isolate_host":    {"title": "Isolate host",         "reversible": True,  "target_kind": "host"},
    "block_ip":        {"title": "Block C2 address",     "reversible": True,  "target_kind": "ip"},
    "disable_account": {"title": "Disable account",      "reversible": True,  "target_kind": "user"},
    "kill_process":    {"title": "Kill process",         "reversible": False, "target_kind": "process"},
    "snapshot":        {"title": "Snapshot / forensics", "reversible": True,  "target_kind": "host"},
}


def recommend(incident: Incident) -> list[dict]:
    """Map a correlated incident to recommended response actions, most-contained
    first. Reversible-first — nothing here is auto-executed; each is a proposal
    for the human gate."""
    phases = incident.phases
    entity = incident.entity
    recs: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(playbook: str, target: str | None, reason: str) -> None:
        key = (playbook, target or "")
        if target and key not in seen:
            seen.add(key)
            recs.append({"playbook": playbook, "target": target,
                         "reversible": CATALOG[playbook]["reversible"], "reason": reason})

    # contain the host itself when the intrusion spans phases
    if {"lateral_movement", "command_and_control"} & phases:
        add("isolate_host", entity, "multi-phase intrusion on this host — cut lateral movement and C2")

    for e in incident.timeline():
        if e.event_type == "network_flow" and e.src_internal is False and (e.dst_ip or e.dst_host):
            add("block_ip", e.dst_ip or e.dst_host, "outbound connection to an external address (possible C2)")
        if e.event_type == "auth" and e.source_entity:
            add("disable_account", e.source_entity, "account used to move between hosts")

    # always offer read-only evidence capture
    add("snapshot", entity, "capture volatile evidence (processes, connections, logins) before containment")
    return recs
