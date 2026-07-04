from __future__ import annotations

from fastapi import APIRouter, HTTPException

from prahari.api.demo import demo_incidents, incident_id
from prahari.api.models import IncidentDetail, IncidentSummary, MetricsView
from prahari.api.serialize import to_detail, to_summary

router = APIRouter(prefix="/api")


@router.get("/metrics", response_model=MetricsView)
def metrics() -> MetricsView:
    # real LANL benchmark (docs/benchmarks/lanl-real-results.md)
    return MetricsView(behavioural_recall=0.794, signature_recall=0.0,
                       mttd_seconds=41, attack_techniques=697, false_positive_rate=0.075)


@router.get("/incidents", response_model=list[IncidentSummary])
def incidents() -> list[IncidentSummary]:
    summaries = [to_summary(i) for i in demo_incidents()]
    summaries.sort(key=lambda s: s.compound_score, reverse=True)
    return summaries


@router.get("/incidents/{incident_id_}", response_model=IncidentDetail)
def incident(incident_id_: str) -> IncidentDetail:
    for inc in demo_incidents():
        if incident_id(inc) == incident_id_:
            return to_detail(inc)
    raise HTTPException(status_code=404, detail="incident not found")
