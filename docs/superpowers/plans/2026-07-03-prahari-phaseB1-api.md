# Prahari Phase B1 (Dashboard API): FastAPI Incident + Metrics Endpoints

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the correlated-incident + ATT&CK-attribution + benchmark data over a small JSON API so the Next.js SOC dashboard (Phase B2) can render the command view, the C553 incident-detail hero, and the proof panel.

**Architecture:** A deterministic demo scenario builds real `Incident` objects through the Phase 3 correlator and attaches the recorded (real) attribution + prediction — so the API is fast and needs no live Ollama. Pydantic view models serialize incidents; FastAPI routes serve them; CORS lets the Next.js dev server (port 3000) call the API (port 8000).

**Tech Stack:** Python 3.14 + uv, FastAPI (already present), pytest + TestClient. Builds on Phase 3 `Incident`/`correlate` and Phase 4 attribution data.

## Global Constraints

- Package root `apps/api`, package `prahari`; tests: `cd apps/api && uv run pytest`.
- No live Ollama in request handling — attribution values are the recorded output from `docs/benchmarks/attribution-demo.md` (T1021.006 / T1057 / T1071.002), served statically. The incident structure is built by the real correlator.
- Metrics endpoint returns the real LANL benchmark numbers (recall 0.794 behavioural / 0.0 signature) from `docs/benchmarks/lanl-real-results.md`.
- All view models are Pydantic v2; timestamps serialized ISO-8601.
- CORS allows `http://localhost:3000`.
- Commit after every task with the message in its final step.

---

### Task 1: API view models

**Files:**
- Create: `apps/api/prahari/api/__init__.py`
- Create: `apps/api/prahari/api/models.py`
- Create: `apps/api/tests/test_api_models.py`

**Interfaces:**
- Consumes: nothing.
- Produces (all Pydantic `BaseModel`):
  - `EventView`: `timestamp: datetime`, `event_type: str`, `phase: str`, `source: str`, `actor: str | None`, `detail: str`.
  - `TechniqueView`: `id: str`, `name: str`, `tactic: str`.
  - `AttributionView`: `technique_ids: list[str]`, `techniques: list[TechniqueView]`, `explanation: str`, `grounded: bool`, `predicted_next: str`.
  - `IncidentSummary`: `id: str`, `entity: str`, `compound_score: float`, `high_confidence: bool`, `is_true_positive: bool`, `phase_count: int`, `source_count: int`, `event_count: int`, `start: datetime`.
  - `IncidentDetail`: `summary: IncidentSummary`, `timeline: list[EventView]`, `attribution: AttributionView`.
  - `MetricsView`: `behavioural_recall: float`, `signature_recall: float`, `mttd_seconds: int`, `attack_techniques: int`, `false_positive_rate: float`.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_api_models.py`:
```python
from datetime import datetime, timezone

from prahari.api.models import (
    AttributionView, EventView, IncidentSummary, MetricsView, TechniqueView,
)


def test_models_construct_and_serialize():
    ev = EventView(timestamp=datetime(2017, 7, 5, 15, 32, 16, tzinfo=timezone.utc),
                   event_type="auth", phase="lateral_movement", source="lanl",
                   actor="U342@DOM1", detail="remote login (NTLM) to C553")
    assert ev.model_dump()["phase"] == "lateral_movement"

    attr = AttributionView(technique_ids=["T1021.006"],
                           techniques=[TechniqueView(id="T1021.006", name="Remote Services", tactic="lateral-movement")],
                           explanation="lateral movement", grounded=True, predicted_next="exfiltration")
    assert attr.grounded is True

    summ = IncidentSummary(id="inc-c553", entity="C553", compound_score=0.94, high_confidence=True,
                           is_true_positive=True, phase_count=3, source_count=3, event_count=3,
                           start=datetime(2017, 7, 5, 15, 32, 16, tzinfo=timezone.utc))
    assert summ.high_confidence is True

    m = MetricsView(behavioural_recall=0.794, signature_recall=0.0, mttd_seconds=41,
                    attack_techniques=697, false_positive_rate=0.075)
    assert m.behavioural_recall == 0.794
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_api_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.api'`

- [ ] **Step 3: Implement**

`apps/api/prahari/api/__init__.py`: (empty file)

`apps/api/prahari/api/models.py`:
```python
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class EventView(BaseModel):
    timestamp: datetime
    event_type: str
    phase: str
    source: str
    actor: str | None = None
    detail: str


class TechniqueView(BaseModel):
    id: str
    name: str
    tactic: str


class AttributionView(BaseModel):
    technique_ids: list[str]
    techniques: list[TechniqueView]
    explanation: str
    grounded: bool
    predicted_next: str


class IncidentSummary(BaseModel):
    id: str
    entity: str
    compound_score: float
    high_confidence: bool
    is_true_positive: bool
    phase_count: int
    source_count: int
    event_count: int
    start: datetime


class IncidentDetail(BaseModel):
    summary: IncidentSummary
    timeline: list[EventView]
    attribution: AttributionView


class MetricsView(BaseModel):
    behavioural_recall: float
    signature_recall: float
    mttd_seconds: int
    attack_techniques: int
    false_positive_rate: float
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_api_models.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/api/__init__.py apps/api/prahari/api/models.py apps/api/tests/test_api_models.py
git commit -m "feat(api): dashboard view models"
```

---

### Task 2: Demo scenario builder

**Files:**
- Create: `apps/api/prahari/api/demo.py`
- Create: `apps/api/tests/test_demo_scenario.py`

**Interfaces:**
- Consumes: `CanonicalEvent`, `correlate`, `target_of`, `Incident`, Phase 4 attribution constants.
- Produces:
  - `demo_incidents() -> list[Incident]` — builds, via the real `correlate(...)`, the C553 fused incident (auth+process+network, high-confidence, red-team) plus two lower-severity incidents (a single-source benign burst and a two-source medium incident) so the command view has range.
  - `ATTRIBUTIONS: dict[str, dict]` — recorded attribution per incident id (C553 → T1021.006/T1057/T1071.002 + explanation + predicted_next `exfiltration`).
  - `incident_id(incident) -> str` — stable id `inc-<entity>` lowercased.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_demo_scenario.py`:
```python
from prahari.api.demo import ATTRIBUTIONS, demo_incidents, incident_id


def test_demo_has_c553_high_confidence_incident():
    incidents = demo_incidents()
    ids = {incident_id(i) for i in incidents}
    assert "inc-c553" in ids

    c553 = next(i for i in incidents if incident_id(i) == "inc-c553")
    assert c553.high_confidence is True
    assert c553.is_true_positive is True
    assert len(c553.sources) == 3
    assert len(c553.phases) == 3


def test_c553_has_recorded_attribution():
    attr = ATTRIBUTIONS["inc-c553"]
    assert "T1021.006" in attr["technique_ids"]
    assert attr["predicted_next"] == "exfiltration"
    assert attr["grounded"] is True
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_demo_scenario.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.api.demo'`

- [ ] **Step 3: Implement**

`apps/api/prahari/api/demo.py`:
```python
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
            "NTLM remote login to a critical host (lateral movement), followed by whoami "
            "process discovery, then an outbound beacon to a new external address — a "
            "textbook low-and-slow intrusion fused from three sensors."
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_demo_scenario.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/api/demo.py apps/api/tests/test_demo_scenario.py
git commit -m "feat(api): demo incident scenario with recorded attribution"
```

---

### Task 3: Serializers (incident → view models)

**Files:**
- Create: `apps/api/prahari/api/serialize.py`
- Create: `apps/api/tests/test_serialize.py`

**Interfaces:**
- Consumes: `Incident`, `killchain_phase`, `actor_of`, view models, `ATTRIBUTIONS`, `incident_id`.
- Produces:
  - `event_view(e: CanonicalEvent) -> EventView` — uses `killchain_phase` for `phase` and the same field-derived `detail` phrasing as the attributor (`remote login (NTLM) to C553`, `executed ...`, `outbound external connection to ...`).
  - `to_summary(incident: Incident) -> IncidentSummary`.
  - `to_detail(incident: Incident) -> IncidentDetail` — attaches `ATTRIBUTIONS[incident_id]` if present, else an empty attribution (`grounded=False`, `predicted_next=""`).

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_serialize.py`:
```python
from prahari.api.demo import demo_incidents, incident_id
from prahari.api.serialize import to_detail, to_summary


def _c553():
    return next(i for i in demo_incidents() if incident_id(i) == "inc-c553")


def test_summary_fields():
    s = to_summary(_c553())
    assert s.id == "inc-c553"
    assert s.entity == "C553"
    assert s.high_confidence is True
    assert s.source_count == 3
    assert s.phase_count == 3
    assert s.compound_score > 0.8


def test_detail_timeline_and_attribution():
    d = to_detail(_c553())
    assert [e.event_type for e in d.timeline] == ["auth", "process", "network_flow"]
    assert d.timeline[0].phase == "lateral_movement"
    assert "C553" in d.timeline[0].detail
    assert "T1021.006" in d.attribution.technique_ids
    assert d.attribution.predicted_next == "exfiltration"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_serialize.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.api.serialize'`

- [ ] **Step 3: Implement**

`apps/api/prahari/api/serialize.py`:
```python
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
        source=e.source, actor=actor_of(e), detail=_detail(e),
    )


def to_summary(incident: Incident) -> IncidentSummary:
    return IncidentSummary(
        id=incident_id(incident), entity=incident.entity,
        compound_score=incident.compound_score, high_confidence=incident.high_confidence,
        is_true_positive=incident.is_true_positive, phase_count=len(incident.phases),
        source_count=len(incident.sources), event_count=len(incident.events),
        start=incident.start,
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


def to_detail(incident: Incident) -> IncidentDetail:
    return IncidentDetail(
        summary=to_summary(incident),
        timeline=[event_view(e) for e in incident.timeline()],
        attribution=_attribution(incident),
    )
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_serialize.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/api/serialize.py apps/api/tests/test_serialize.py
git commit -m "feat(api): incident serializers"
```

---

### Task 4: API routes + CORS + wire into app

**Files:**
- Create: `apps/api/prahari/api/routes.py`
- Modify: `apps/api/prahari/main.py`
- Create: `apps/api/tests/test_api_routes.py`

**Interfaces:**
- Consumes: `demo_incidents`, `incident_id`, `to_summary`, `to_detail`, `MetricsView`, FastAPI.
- Produces:
  - `router: APIRouter` with `GET /api/metrics` → `MetricsView`; `GET /api/incidents` → `list[IncidentSummary]` (sorted by compound desc); `GET /api/incidents/{incident_id}` → `IncidentDetail` (404 if unknown).
  - `main.py` includes the router and adds CORS for `http://localhost:3000`.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_api_routes.py`:
```python
from fastapi.testclient import TestClient

from prahari.main import app

client = TestClient(app)


def test_metrics_endpoint():
    r = client.get("/api/metrics")
    assert r.status_code == 200
    assert r.json()["signature_recall"] == 0.0
    assert r.json()["behavioural_recall"] > 0.5


def test_incidents_list_sorted_and_c553_present():
    r = client.get("/api/incidents")
    assert r.status_code == 200
    data = r.json()
    ids = [i["id"] for i in data]
    assert "inc-c553" in ids
    scores = [i["compound_score"] for i in data]
    assert scores == sorted(scores, reverse=True)
    assert data[0]["id"] == "inc-c553"  # highest compound


def test_incident_detail_and_404():
    r = client.get("/api/incidents/inc-c553")
    assert r.status_code == 200
    body = r.json()
    assert body["attribution"]["technique_ids"][0] == "T1021.006"
    assert len(body["timeline"]) == 3
    assert client.get("/api/incidents/nope").status_code == 404
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_api_routes.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.api.routes'`

- [ ] **Step 3: Implement the router**

`apps/api/prahari/api/routes.py`:
```python
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
```

- [ ] **Step 4: Wire router + CORS into main.py**

Replace the contents of `apps/api/prahari/main.py` with:
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from prahari.api.routes import router

app = FastAPI(title="Prahari", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "prahari"}
```

- [ ] **Step 5: Run to verify it passes (plus health regression)**

Run: `cd apps/api && uv run pytest tests/test_api_routes.py tests/test_health.py -v`
Expected: PASS

- [ ] **Step 6: Run the full suite (Phase B1 exit gate)**

Run: `cd apps/api && uv run pytest -q`
Expected: PASS — all prior + API tests green.

- [ ] **Step 7: Commit**

```bash
git add apps/api/prahari/api/routes.py apps/api/prahari/main.py apps/api/tests/test_api_routes.py
git commit -m "feat(api): incident + metrics routes with CORS (Phase B1 exit gate)"
```

---

## Self-Review

**Spec coverage (dashboard API):**
- Serve incidents/timeline/attribution/metrics for the SOC dashboard (spec §12) → Tasks 1–4 ✅
- Real correlator builds the C553 fused incident (spec §4) → Task 2 ✅
- Real benchmark metrics surfaced (spec §10) → Task 4 ✅
- CORS for the Next.js client → Task 4 ✅
- Deferred to B2 (correct): the Next.js UI; deferred later: SSE live replay, respond POST, audit-log endpoint.

**Placeholder scan:** No TBD/TODO. Attribution values are the *recorded real* output (documented provenance), not invented placeholders.

**Type consistency:** view models (Task 1) consumed by serializers (Task 3) and routes (Task 4). `incident_id(incident) -> str`, `demo_incidents() -> list[Incident]` (Task 2) used in Tasks 3, 4. `to_summary`/`to_detail` (Task 3) used in routes (Task 4). Route path param `incident_id_` avoids shadowing the imported `incident_id` function. `MetricsView` fields identical in model (Task 1), route (Task 4), and test.
