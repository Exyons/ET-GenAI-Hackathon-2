from __future__ import annotations

from prahari.correlate.incident import Incident
from prahari.live.netinfo import classify

# Playbook catalog. Command implementations live on the agent (OS-specific);
# the API only stores the recommendation. `what` / `impact` explain the action in
# plain language for the operator at the human gate.
CATALOG = {
    "isolate_host": {
        "title": "Isolate host", "reversible": True, "target_kind": "host",
        "what": "Installs a host firewall rule that drops all outbound traffic except "
                "the management port (SSH/22) and already-established connections.",
        "impact": "The host can no longer reach other machines or the internet, so "
                  "lateral movement and command-and-control are cut. Legitimate services "
                  "on the host also stop talking out until you revert.",
    },
    "block_ip": {
        "title": "Block address", "reversible": True, "target_kind": "ip",
        "what": "Installs a firewall rule that drops all traffic to this single address.",
        "impact": "Only traffic to this one address is blocked — everything else on the "
                  "host keeps working. Reversible.",
    },
    "disable_account": {
        "title": "Disable account", "reversible": True, "target_kind": "user",
        "what": "Locks the user account (usermod -L) so it can no longer authenticate.",
        "impact": "This account can't log in anywhere it's used until re-enabled. Existing "
                  "sessions are not killed. Reversible.",
    },
    "kill_process": {
        "title": "Kill process", "reversible": False, "target_kind": "process",
        "what": "Terminates the matching process and its children (pkill).",
        "impact": "The process stops immediately. This cannot be undone — use when a "
                  "malicious binary is actively running.",
    },
    "snapshot": {
        "title": "Snapshot / forensics", "reversible": True, "target_kind": "host",
        "what": "Read-only. Captures the current process list, network connections and "
                "recent logins on the host.",
        "impact": "Nothing on the host is changed — this only collects evidence for the "
                  "investigation, so it runs even in dry-run.",
    },
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

    phase_list = " → ".join(p.replace("_", " ") for p in
                            sorted(phases, key=lambda p: ("lateral_movement", "discovery",
                                                          "execution", "command_and_control").index(p)
                                   if p in ("lateral_movement", "discovery", "execution",
                                            "command_and_control") else 9))

    # contain the host itself when the intrusion spans phases
    if {"lateral_movement", "command_and_control"} & phases:
        add("isolate_host", entity,
            f"This host shows a multi-phase intrusion ({phase_list}) across "
            f"{len(incident.sources)} sensors — isolating it stops the attacker moving further.")

    for e in incident.timeline():
        # only propose blocking a routable PUBLIC address — never an internal/local
        # one (blocking those would break the network and just clutters the queue)
        if e.event_type == "network_flow" and e.dst_ip and classify(e.dst_ip)["klass"] == "public":
            add("block_ip", e.dst_ip,
                f"{entity} made an outbound connection to this public address — a likely "
                "command-and-control channel. Click the address for connection detail.")
        if e.event_type == "auth" and e.source_entity:
            add("disable_account", e.source_entity,
                f"'{e.source_entity}' was used to authenticate into this host during the "
                "intrusion — locking it denies the attacker that credential.")

    # always offer read-only evidence capture
    add("snapshot", entity,
        "Capture volatile evidence (running processes, live connections, recent logins) "
        "now, before any containment changes the host's state.")
    return recs
