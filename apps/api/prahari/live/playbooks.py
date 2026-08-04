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
        "what": "Read-only. Resolves every live socket to the process that owns it, then "
                "reports that process's binary, parent chain, user and hash — plus any "
                "recently-planted persistence.",
        "impact": "Nothing on the host is changed — this only collects evidence for the "
                  "investigation, so it runs even in dry-run.",
    },
}

# ---- response ladder --------------------------------------------------------
# Containment is graduated. Each tier is the least disruptive action that still
# addresses the evidence, and the system must justify climbing to the next one.
TIERS = {
    0: ("observe", "Watch and collect. The evidence does not yet justify touching the host."),
    1: ("precision", "Cut the specific channels the attacker is using, nothing else."),
    2: ("vector", "Deny the credential and the process the attacker is working through."),
    3: ("isolate", "Last resort — sever the host from the network entirely."),
}

# Isolation is the most destructive reversible action we have; it only becomes a
# recommendation when the precise options provably cannot contain the intrusion.
SPREAD_HOSTS = 2      # attacker already established on this many other hosts
UNPINNABLE_IPS = 20   # too many distinct C2 addresses to block one at a time
DESTRUCTIVE_PHASES = {"impact", "exfiltration"}


def _c2_addresses(incident: Incident) -> list[str]:
    """Public destinations only — blocking an internal address breaks the network
    and tells us nothing."""
    out: list[str] = []
    for e in incident.timeline():
        if (e.event_type == "network_flow" and e.dst_ip
                and classify(e.dst_ip)["klass"] == "public" and e.dst_ip not in out):
            out.append(e.dst_ip)
    return out


def _accounts(incident: Incident) -> list[str]:
    out: list[str] = []
    for e in incident.timeline():
        if e.event_type == "auth" and e.source_entity and e.source_entity not in out:
            out.append(e.source_entity)
    return out


def _commands(incident: Incident) -> list[str]:
    out: list[str] = []
    for e in incident.timeline():
        if e.event_type == "process" and e.dest_entity and e.dest_entity not in out:
            out.append(e.dest_entity)
    return out


def spread_hosts(incident: Incident, peers: list[Incident] | None) -> list[str]:
    """Other hosts where the same account is already implicated. This is the
    signal that per-address blocking cannot contain the intrusion — the attacker
    is moving *inside* the network, where no outbound rule applies."""
    if not peers:
        return []
    mine = set(_accounts(incident))
    if not mine:
        return []
    out = []
    for p in peers:
        if p.entity != incident.entity and mine & set(_accounts(p)) and p.entity not in out:
            out.append(p.entity)
    return sorted(out)


def isolation_case(incident: Incident, peers: list[Incident] | None = None,
                   predicted_next: str = "") -> tuple[bool, str]:
    """Should isolation be recommended, and why (or why not)?

    Returning the negative case is the point: an operator staring at a live
    intrusion needs to know what already covers it, so 'isolate everything'
    stops being the reflex."""
    spread = spread_hosts(incident, peers)
    c2 = _c2_addresses(incident)
    phases = incident.phases

    if len(spread) >= SPREAD_HOSTS:
        return True, (f"The same credential is already implicated on {len(spread)} other hosts "
                      f"({', '.join(spread[:4])}). Lateral movement is internal traffic, so "
                      "blocking outbound addresses cannot stop it — isolation can.")
    if DESTRUCTIVE_PHASES & phases:
        return True, ("Destructive activity is under way. Containing the host outweighs "
                      "keeping its services reachable.")
    if len(c2) > UNPINNABLE_IPS:
        return True, (f"{len(c2)} distinct external addresses in one window — the channel is "
                      "rotating faster than per-address blocking can keep up.")
    if "command_and_control" in phases and not c2:
        return True, ("Command-and-control behaviour is present but no address could be pinned "
                      "to it, so there is nothing precise to block.")

    # --- not recommended: say what covers it instead ---
    if c2:
        return False, (f"Not recommended. Blocking the {len(c2)} identified "
                       f"address{'es' if len(c2) != 1 else ''} closes this channel without "
                       "cutting the host's legitimate traffic. Escalate if new addresses keep "
                       "appearing, or if the account turns up on other hosts.")
    if predicted_next:
        return False, (f"Not recommended yet. The predicted next move is {predicted_next.replace('_', ' ')} "
                       "— capture forensics first so containment does not destroy the evidence.")
    return False, ("Not recommended. Nothing here is beyond the reach of the precise actions "
                   "above, and isolation would stop the host doing its job.")


def assess(incident: Incident, peers: list[Incident] | None = None,
           predicted_next: str = "") -> dict:
    """Pick the response tier from the evidence, not from a phase keyword match."""
    c2 = _c2_addresses(incident)
    accounts = _accounts(incident)
    commands = _commands(incident)
    isolate, isolate_note = isolation_case(incident, peers, predicted_next)
    spread = spread_hosts(incident, peers)

    if isolate:
        tier = 3
    elif accounts and ({"execution", "lateral_movement"} & incident.phases):
        tier = 2
    elif c2:
        tier = 1
    else:
        tier = 0

    name, rationale = TIERS[tier]
    return {
        "tier": tier, "tier_name": name, "rationale": rationale,
        "isolate": isolate, "isolate_note": isolate_note,
        "c2": c2, "accounts": accounts, "commands": commands, "spread": spread,
    }


def recommend(incident: Incident, peers: list[Incident] | None = None,
              predicted_next: str = "") -> list[dict]:
    """Map a correlated incident to response actions, least disruptive first.

    Nothing is auto-executed — each entry is a proposal for the human gate. The
    tier on each action tells the UI whether it is a first-line action or an
    escalation the operator has to reach for deliberately."""
    a = assess(incident, peers, predicted_next)
    entity = incident.entity
    recs: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(playbook: str, target: str | None, reason: str, tier: int,
            escalation: bool = False, note: str = "", params: dict | None = None) -> None:
        key = (playbook, target or "")
        if target and key not in seen:
            seen.add(key)
            recs.append({"playbook": playbook, "target": target,
                         "reversible": CATALOG[playbook]["reversible"],
                         "reason": reason, "tier": tier, "escalation": escalation,
                         "gate_note": note, "params": params or {}})

    # Tier 0 — always: evidence first, before containment changes the host's state.
    # It carries the incident's own IOCs so the collector can attribute them.
    add("snapshot", entity,
        "Resolve the live sockets to the processes that own them, before any containment "
        "changes the host's state.", tier=0,
        params={"ips": a["c2"], "commands": a["commands"][:12]})

    # Tier 1 — precision: the specific channels in evidence.
    for ip in a["c2"]:
        add("block_ip", ip,
            f"{entity} made an outbound connection to this public address — a likely "
            "command-and-control channel. Click the address for connection detail.", tier=1)

    # Tier 2 — the vector: the credential and the process being used.
    if a["tier"] >= 2:
        for acct in a["accounts"]:
            add("disable_account", acct,
                f"'{acct}' was used to authenticate into this host during the intrusion — "
                "locking it denies the attacker that credential.", tier=2)
        for cmd in a["commands"][:5]:
            add("kill_process", cmd,
                f"'{cmd[:80]}' ran on {entity} as part of this intrusion. Run forensics first "
                "— killing it destroys volatile evidence.", tier=2)

    # Tier 3 — isolation. Offered either way, but only *recommended* when the
    # precise actions provably cannot contain it; otherwise it is an escalation
    # and `gate_note` carries the argument against reaching for it yet.
    add("isolate_host", entity,
        a["isolate_note"] if a["isolate"]
        else f"Severs {entity} from the network — every outbound connection except the "
             "management port. Consider it only once the actions above are exhausted.",
        tier=3, escalation=not a["isolate"], note="" if a["isolate"] else a["isolate_note"])

    recs.sort(key=lambda r: r["tier"])
    return recs
