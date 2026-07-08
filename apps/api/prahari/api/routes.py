from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import StreamingResponse

from prahari import config
from prahari.api.demo import demo_incidents, incident_id
from prahari.api.models import IncidentDetail, IncidentSummary, MetricsView
from prahari.api.serialize import to_detail, to_summary
from prahari.live.state import bus, pipeline
from prahari.schema import CanonicalEvent

router = APIRouter(prefix="/api")


def require_token(authorization: str = Header(default="")) -> None:
    if authorization != f"Bearer {config.INGEST_TOKEN}":
        raise HTTPException(status_code=401, detail="invalid ingest token")


@router.get("/metrics", response_model=MetricsView)
def metrics() -> MetricsView:
    # real LANL benchmark (docs/benchmarks/lanl-real-results.md)
    return MetricsView(behavioural_recall=0.794, signature_recall=0.0,
                       mttd_seconds=41, attack_techniques=697, false_positive_rate=0.075)


@router.post("/ingest")
async def ingest(events: list[CanonicalEvent], _: None = Depends(require_token)) -> dict:
    await pipeline.ingest(events)
    return {"accepted": len(events), "mode": pipeline.mode}


@router.get("/status")
def status() -> dict:
    return pipeline.status()


@router.post("/baseline/reset")
def baseline_reset(_: None = Depends(require_token)) -> dict:
    # the ONLY path back into warmup — a deliberate operator action, not a process restart
    pipeline.reset_baseline()
    return {"mode": pipeline.mode}


@router.get("/stream")
async def stream() -> StreamingResponse:
    async def _sse():
        async for evt in bus.subscribe():
            yield f"data: {json.dumps(evt)}\n\n"

    return StreamingResponse(_sse(), media_type="text/event-stream")


@router.get("/incidents", response_model=list[IncidentSummary])
def incidents() -> list[IncidentSummary]:
    source = pipeline.incidents.values() if pipeline.incidents else demo_incidents()
    summaries = [to_summary(i) for i in source]
    summaries.sort(key=lambda s: s.compound_score, reverse=True)
    return summaries


@router.get("/incidents/{incident_id_}", response_model=IncidentDetail)
def incident(incident_id_: str) -> IncidentDetail:
    live = pipeline.incidents.get(incident_id_)
    if live is not None:
        return to_detail(live, pipeline.attributions.get(incident_id_))
    for inc in demo_incidents():
        if incident_id(inc) == incident_id_:
            return to_detail(inc)
    raise HTTPException(status_code=404, detail="incident not found")
