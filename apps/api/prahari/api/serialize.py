from __future__ import annotations

from prahari.api.demo import ATTRIBUTIONS, incident_id
from prahari.api.models import (
    AttributionView, EventView, IncidentDetail, IncidentSummary, TechniqueView,
)
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import actor_of, killchain_phase
from prahari.schema import CanonicalEvent


def _detail(e: CanonicalEvent) -> str:
    if e.event_type == "auth":
        mech = f" ({e.auth_type})" if e.auth_type else ""
        return f"remote login{mech} to {e.dst_host or ''}".strip()
    if e.event_type == "process":
        return f"executed {e.dest_entity or ''}".strip()
    if e.event_type == "network_flow":
        scope = "external " if e.src_internal is False else ""
        return f"outbound {scope}connection to {e.dst_ip or e.dst_host or ''}".strip()
    return e.dest_entity or e.dst_host or e.dst_ip or ""


def event_view(e: CanonicalEvent) -> EventView:
    return EventView(
        timestamp=e.timestamp, event_type=e.event_type, phase=killchain_phase(e),
        source=e.source, actor=actor_of(e), detail=_detail(e), dst_ip=e.dst_ip,
    )


def to_summary(incident: Incident) -> IncidentSummary:
    phases: list[str] = []
    sources: list[str] = []
    for e in incident.timeline():
        p = killchain_phase(e)
        if p not in phases:
            phases.append(p)
        if e.source not in sources:
            sources.append(e.source)
    return IncidentSummary(
        id=incident_id(incident), entity=incident.entity,
        compound_score=incident.compound_score, high_confidence=incident.high_confidence,
        is_true_positive=incident.is_true_positive, phase_count=len(incident.phases),
        source_count=len(incident.sources), event_count=len(incident.events),
        start=incident.start, end=incident.end, phases=phases, sources=sources,
    )


def _attribution(incident: Incident) -> AttributionView:
    data = ATTRIBUTIONS.get(incident_id(incident))
    if not data:
        return AttributionView(technique_ids=[], techniques=[], explanation="",
                               grounded=False, predicted_next="")
    return AttributionView(
        technique_ids=data["technique_ids"],
        techniques=[TechniqueView(**t) for t in data["techniques"]],
        explanation=data["explanation"], grounded=data["grounded"],
        predicted_next=data["predicted_next"],
    )


def to_detail(incident: Incident, attribution: AttributionView | None = None) -> IncidentDetail:
    # live incidents pass a computed AttributionView; the demo path passes None and
    # falls back to the module-global ATTRIBUTIONS lookup.
    return IncidentDetail(
        summary=to_summary(incident),
        timeline=[event_view(e) for e in incident.timeline()],
        attribution=attribution if attribution is not None else _attribution(incident),
    )
