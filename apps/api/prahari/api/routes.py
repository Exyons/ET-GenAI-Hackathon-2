from __future__ import annotations

import json
from dataclasses import asdict

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from prahari import config
from prahari.api.demo import demo_incidents, incident_id
from prahari.api.models import IncidentDetail, IncidentSummary, MetricsView
from prahari.api.serialize import event_view, to_detail, to_summary
from prahari.correlate.killchain import target_of
from prahari.live.fleet import TAPE_SIZE
from prahari.live.state import action_store, bus, pipeline
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
async def ingest(
    events: list[CanonicalEvent],
    _: None = Depends(require_token),
    x_prahari_host: str = Header(default=""),
    x_prahari_os: str = Header(default=""),
    x_prahari_sources: str = Header(default=""),
    x_prahari_source_status: str = Header(default=""),
) -> dict:
    # collector heartbeat: an empty batch with these headers keeps the host
    # visible in the fleet even before any telemetry event fires
    if x_prahari_host:
        agent = None
        if x_prahari_source_status:
            try:
                agent = json.loads(x_prahari_source_status)
            except ValueError:
                agent = None
        pipeline.fleet.heartbeat(x_prahari_host, x_prahari_os,
                                 [s for s in x_prahari_sources.split(",") if s], agent)
    await pipeline.ingest(events)
    return {"accepted": len(events), "mode": pipeline.mode}


@router.get("/status")
def status() -> dict:
    return pipeline.status()


@router.get("/events/recent")
def events_recent(limit: int = Query(default=100, ge=1, le=TAPE_SIZE)) -> list[dict]:
    # newest-last tape of raw telemetry for the command deck's initial render;
    # afterwards the UI follows the SSE "telemetry" frames.
    tape = list(pipeline.fleet.tape)
    return tape[-limit:]


@router.get("/events/flagged")
def events_flagged() -> list[dict]:
    # every event the sentinels flagged inside the correlation window —
    # the population behind the FLAGGED tile
    return [{**event_view(e).model_dump(mode="json"),
             "host": target_of(e) or e.src_host or "unknown", "flagged": True}
            for e in pipeline.recent]


_EXPORT_COLS = ["timestamp", "host", "event_type", "phase", "source", "actor", "detail", "dst_ip", "flagged"]


def _csv_cell(v) -> str:
    s = "" if v is None else str(v)
    return f'"{s.replace(chr(34), chr(34) * 2)}"' if any(c in s for c in ',"\n') else s


@router.get("/events/export")
def export_events(view: str = "recent", format: str = "json") -> Response:
    if view == "flagged":
        rows = [{**event_view(e).model_dump(mode="json"),
                 "host": target_of(e) or e.src_host or "unknown", "flagged": True}
                for e in pipeline.recent]
    else:
        rows = list(pipeline.fleet.tape)
    fname = f"prahari-telemetry-{view}"
    if format == "csv":
        lines = [",".join(_EXPORT_COLS)]
        lines += [",".join(_csv_cell(r.get(c)) for c in _EXPORT_COLS) for r in rows]
        return Response("\n".join(lines), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.csv"'})
    return Response(json.dumps(rows, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.json"'})


@router.get("/summary")
def summary(refresh: bool = False) -> dict:
    from prahari import config
    from prahari.attribute.ollama import ollama_chat
    from prahari.live.summary import get_summary

    def chat(prompt: str) -> str:
        return ollama_chat(prompt, model=config.CHAT_MODEL, host=config.OLLAMA_HOST)

    return {**get_summary(pipeline, chat, force=refresh), "model": config.CHAT_MODEL}


@router.get("/events/incidents")
def events_incidents(high: bool = False) -> list[dict]:
    # events belonging to live correlated incidents (optionally high-confidence only)
    out = []
    for inc in pipeline.incidents.values():
        if high and not inc.high_confidence:
            continue
        iid = incident_id(inc)
        for e in inc.timeline():
            out.append({**event_view(e).model_dump(mode="json"),
                        "host": target_of(e) or e.src_host or "unknown",
                        "flagged": True, "incident": iid})
    out.sort(key=lambda d: d["timestamp"])
    return out


@router.post("/baseline/reset")
def baseline_reset(_: None = Depends(require_token)) -> dict:
    # the ONLY path back into warmup — a deliberate operator action, not a process restart
    pipeline.reset_baseline()
    return {"mode": pipeline.mode}


# ---- response / actions ----
# Operator endpoints (approve/reject/revert) are unauthenticated like the rest of
# the read API — the true safety gate is that the AGENT needs the bearer token to
# fetch and execute, actions default to dry_run, and armed execution additionally
# requires PRAHARI_ALLOW_ARMED on the agent. Agent endpoints (pending/result) are
# bearer-gated: that is the command channel.
class ApproveBody(BaseModel):
    approver: str = "operator"
    arm: bool = False


class DecisionBody(BaseModel):
    approver: str = "operator"


class ResultBody(BaseModel):
    ran: bool = False
    dry_run: bool = True
    command: str = ""
    stdout: str = ""
    exit_code: int | None = None
    error: str | None = None
    note: str = ""


def _require_action(aid: str):
    a = action_store.get(aid)
    if a is None:
        raise HTTPException(status_code=404, detail="action not found")
    return a


@router.get("/playbooks")
def playbooks_catalog() -> dict:
    from prahari.live.playbooks import CATALOG
    return {k: {"title": v["title"], "reversible": v["reversible"],
                "what": v["what"], "impact": v["impact"]} for k, v in CATALOG.items()}


@router.get("/network/{ip}")
def network_detail(ip: str) -> dict:
    from prahari.live import threatintel
    from prahari.live.netinfo import classify

    info = classify(ip)
    ti = threatintel.enrich(ip)
    listed = ti["reputation"]["listed"]
    if listed:
        verdict, severity = "Malicious — on blocklist", "bad"
    elif info["scope"] in ("internal", "local"):
        verdict, severity = "Internal / trusted range", "good"
    elif ti["provider"]:
        verdict, severity = f"External — {ti['provider']}", "neutral"
    else:
        verdict, severity = "External — unclassified", "neutral"

    flows = [f for f in pipeline.fleet.flows if f["dst_ip"] == ip]
    hosts = sorted({f["src_host"] for f in flows if f["src_host"]})
    times = [f["ts"] for f in flows]
    return {
        "ip": ip, **info, **ti,
        "verdict": verdict, "severity": severity,
        "flow_count": len(flows),
        "hosts": hosts,
        "total_bytes": sum(f["bytes"] or 0 for f in flows),
        "first_seen": min(times) if times else None,
        "last_seen": max(times) if times else None,
        "any_flagged": any(f["flagged"] for f in flows),
        "flows": sorted(flows, key=lambda f: f["ts"], reverse=True)[:50],
    }


@router.get("/actions")
def list_actions(incident: str | None = None) -> list[dict]:
    items = [asdict(a) for a in action_store.list()]
    return [a for a in items if a["incident_id"] == incident] if incident else items


@router.post("/actions/{aid}/approve")
def approve_action(aid: str, body: ApproveBody) -> dict:
    _require_action(aid)
    return asdict(action_store.approve(aid, body.approver, body.arm))


@router.post("/actions/{aid}/reject")
def reject_action(aid: str, body: DecisionBody) -> dict:
    _require_action(aid)
    return asdict(action_store.reject(aid, body.approver))


@router.post("/actions/{aid}/revert")
def revert_action(aid: str, body: DecisionBody) -> dict:
    a = _require_action(aid)
    if a.status != "executed" or not a.reversible or (a.result or {}).get("dry_run", True):
        raise HTTPException(status_code=409, detail="only an executed, armed, reversible action can be reverted")
    return asdict(action_store.revert(aid, body.approver))


@router.get("/actions/pending")
def pending_actions(host: str, _: None = Depends(require_token)) -> list[dict]:
    return [asdict(a) for a in action_store.pending_for_host(host)]


@router.post("/actions/{aid}/result")
def action_result(aid: str, body: ResultBody, _: None = Depends(require_token)) -> dict:
    _require_action(aid)
    return asdict(action_store.report(aid, body.model_dump()))


@router.get("/stream")
async def stream() -> StreamingResponse:
    async def _sse():
        async for evt in bus.subscribe():
            yield f"data: {json.dumps(evt)}\n\n"

    return StreamingResponse(_sse(), media_type="text/event-stream")


@router.get("/incidents", response_model=list[IncidentSummary])
def incidents() -> list[IncidentSummary]:
    # live correlated incidents only; the canned scenario lives under /api/demo
    summaries = [to_summary(i) for i in pipeline.incidents.values()]
    summaries.sort(key=lambda s: s.compound_score, reverse=True)
    return summaries


@router.get("/demo/incidents", response_model=list[IncidentSummary])
def demo_incident_list() -> list[IncidentSummary]:
    summaries = [to_summary(i) for i in demo_incidents()]
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
