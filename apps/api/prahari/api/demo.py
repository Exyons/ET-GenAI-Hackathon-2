from __future__ import annotations

from datetime import datetime, timedelta, timezone

from prahari.correlate.correlator import correlate
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import target_of
from prahari.schema import CanonicalEvent

_T0 = datetime(2017, 7, 5, 15, 32, 0, tzinfo=timezone.utc)


def _ev(sec, event_type, source, **kw) -> CanonicalEvent:
    return CanonicalEvent(timestamp=_T0 + timedelta(seconds=sec),
                          event_type=event_type, source=source, raw="x", **kw)


def _raw_events() -> list[CanonicalEvent]:
    return [
        # C553 — the fused red-team lateral-movement story (3 sources, 3 phases)
        _ev(16, "auth", "lanl", source_entity="U342@DOM1", src_host="C1115", dst_host="C553",
            auth_type="NTLM", asset_criticality="critical", labels=["redteam"]),
        _ev(19, "process", "otrf", source_entity="U342@DOM1", src_host="C553",
            dest_entity="cmd /c whoami", asset_criticality="critical"),
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17",
            src_internal=False, asset_criticality="critical"),
        # C988 — medium, two sources
        _ev(40, "auth", "lanl", source_entity="U7@DOM1", src_host="C1", dst_host="C988",
            auth_type="NTLM", asset_criticality="high"),
        _ev(52, "process", "otrf", source_entity="U7@DOM1", src_host="C988",
            dest_entity="powershell -enc ...", asset_criticality="high"),
        # C2100 — low, single benign-looking auth
        _ev(70, "auth", "lanl", source_entity="U55@DOM1", src_host="C9", dst_host="C2100",
            auth_type="Kerberos", asset_criticality="low"),
    ]


def demo_incidents() -> list[Incident]:
    return correlate(_raw_events(), key_fn=target_of, window_seconds=300)


def incident_id(incident: Incident) -> str:
    return f"inc-{incident.entity.lower()}"


ATTRIBUTIONS: dict[str, dict] = {
    "inc-c553": {
        "technique_ids": ["T1021.006", "T1057", "T1071.002"],
        "techniques": [
            {"id": "T1021.006", "name": "Remote Services", "tactic": "lateral-movement"},
            {"id": "T1057", "name": "Process Discovery", "tactic": "discovery"},
            {"id": "T1071.002", "name": "Application Layer Protocol", "tactic": "command-and-control"},
        ],
        "explanation": (
            "An operator authenticated into the critical host C553 over NTLM (T1021.006) — "
            "valid credentials, so no signature fired. Seconds later a process-discovery "
            "command enumerated the host (T1057), and an outbound session opened to a "
            "previously-unseen external address (T1071.002). Individually each step is "
            "ordinary; fused across three sensors they form a hands-on-keyboard intrusion "
            "in its early stages — the actor has a foothold and is orienting before acting "
            "on the objective. Contain C553 now, before data staging or exfiltration begins."
        ),
        "grounded": True,
        "predicted_next": "exfiltration",
    },
    "inc-c988": {
        "technique_ids": ["T1021.006", "T1059.001"],
        "techniques": [
            {"id": "T1021.006", "name": "Remote Services", "tactic": "lateral-movement"},
            {"id": "T1059.001", "name": "PowerShell", "tactic": "execution"},
        ],
        "explanation": "Remote login followed by an encoded PowerShell command on a high-value host.",
        "grounded": True,
        "predicted_next": "discovery",
    },
}
