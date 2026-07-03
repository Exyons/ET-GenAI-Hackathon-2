# Prahari Phase 3 (Correlator): Cross-Source Incident Fusion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fuse anomalous events into per-entity **Incidents** — clustered in time, tagged with kill-chain phases, scored for compound risk — so the fused auth+process+network timeline (the C553 money moment) renders as one object, and clustering collapses thousands of noisy per-event flags into a few high-confidence incidents (the fix for Phase 1.5's 7.5% FPR).

**Architecture:** Pure Python, no external services. `killchain_phase()` maps each event to a coarse ATT&CK phase; `actor_of()`/`target_of()` extract grouping keys. `Incident` bundles a time-clustered set of events for one entity and computes `phases`, `sources`, `compound_score`, and `high_confidence`. `correlate(events, key_fn, window_seconds)` groups events by key and splits each group into time-bounded incidents. Two views: actor-centric (detection / FP reduction) and target-centric (forensic timeline).

**Tech Stack:** Python 3.14 + uv, pytest. Builds on Phase 1 `CanonicalEvent` and Phase 2 `Sentinel` (upstream flags events; the Correlator consumes flagged events).

## Global Constraints

- Package root `apps/api`, package `prahari`; tests: `cd apps/api && uv run pytest`.
- No LLM, no network in this phase (correlation is deterministic).
- `compound_score` returns a float in `[0, 1]`; `high_confidence` requires ≥2 sources AND ≥2 phases.
- Kill-chain phases are strings: `lateral_movement | execution | discovery | command_and_control | unknown`.
- Timestamps are tz-aware UTC; clustering compares `total_seconds()` gaps.
- Commit after every task with the message in its final step.

---

### Task 1: Kill-chain phase tagging + entity key functions

**Files:**
- Create: `apps/api/prahari/correlate/__init__.py`
- Create: `apps/api/prahari/correlate/killchain.py`
- Create: `apps/api/tests/test_killchain.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces:
  - `killchain_phase(event) -> str` — `auth`→`lateral_movement`; `process` with a discovery command→`discovery` else `execution`; `network_flow`→`command_and_control`; otherwise `unknown`.
  - `actor_of(event) -> str | None` — the acting identity (`source_entity`).
  - `target_of(event) -> str | None` — `auth`→`dst_host`; `process`/`network_flow`→`src_host`.
  - `DISCOVERY_COMMANDS: tuple[str, ...]`.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_killchain.py`:
```python
from datetime import datetime, timezone

from prahari.correlate.killchain import actor_of, killchain_phase, target_of
from prahari.schema import CanonicalEvent


def _ev(**kw):
    base = dict(
        timestamp=datetime(2017, 7, 5, 15, tzinfo=timezone.utc),
        source="lanl", raw="x",
    )
    base.update(kw)
    return CanonicalEvent(**base)


def test_phase_for_auth():
    e = _ev(event_type="auth", source_entity="U1", src_host="C1", dst_host="C553")
    assert killchain_phase(e) == "lateral_movement"
    assert actor_of(e) == "U1"
    assert target_of(e) == "C553"


def test_phase_for_process_discovery_vs_execution():
    d = _ev(event_type="process", source_entity="U1", src_host="C553", dest_entity="cmd /c whoami")
    x = _ev(event_type="process", source_entity="U1", src_host="C553", dest_entity="notepad.exe")
    assert killchain_phase(d) == "discovery"
    assert killchain_phase(x) == "execution"
    assert target_of(d) == "C553"


def test_phase_for_network():
    n = _ev(event_type="network_flow", src_host="C553", dst_ip="52.84.23.17")
    assert killchain_phase(n) == "command_and_control"
    assert target_of(n) == "C553"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_killchain.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.correlate'`

- [ ] **Step 3: Implement**

`apps/api/prahari/correlate/__init__.py`: (empty file)

`apps/api/prahari/correlate/killchain.py`:
```python
from __future__ import annotations

from prahari.schema import CanonicalEvent

DISCOVERY_COMMANDS = (
    "whoami", "ipconfig", "net ", "net.exe", "nltest", "systeminfo",
    "tasklist", "arp", "quser", "netstat", "hostname", "wmic",
)


def killchain_phase(event: CanonicalEvent) -> str:
    if event.event_type == "auth":
        return "lateral_movement"
    if event.event_type == "process":
        cmd = (event.dest_entity or "").lower()
        if any(k in cmd for k in DISCOVERY_COMMANDS):
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_killchain.py -v`
Expected: PASS (all three tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/correlate/__init__.py apps/api/prahari/correlate/killchain.py apps/api/tests/test_killchain.py
git commit -m "feat(correlate): kill-chain phase tagging + entity key functions"
```

---

### Task 2: Incident model

**Files:**
- Create: `apps/api/prahari/correlate/incident.py`
- Create: `apps/api/tests/test_incident.py`

**Interfaces:**
- Consumes: `CanonicalEvent`, `killchain_phase`.
- Produces:
  - `class Incident` (dataclass) with `entity: str`, `events: list[CanonicalEvent]` and properties:
    - `start: datetime`, `end: datetime`
    - `phases: set[str]`, `sources: set[str]`
    - `is_true_positive: bool` (any event labelled `redteam` or `attack`)
    - `compound_score: float` in `[0,1]` — rewards source diversity, phase diversity, event count (capped), max asset criticality
    - `high_confidence: bool` — `len(sources) >= 2 and len(phases) >= 2`
    - `timeline() -> list[CanonicalEvent]` — events sorted by timestamp

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_incident.py`:
```python
from datetime import datetime, timezone

from prahari.correlate.incident import Incident
from prahari.schema import CanonicalEvent


def _ev(sec, event_type, source, **kw):
    base = dict(
        timestamp=datetime(2017, 7, 5, 15, 32, sec, tzinfo=timezone.utc),
        event_type=event_type, source=source, raw="x",
    )
    base.update(kw)
    return CanonicalEvent(**base)


def test_single_source_incident_is_low_compound():
    inc = Incident(entity="U1", events=[
        _ev(0, "auth", "lanl", source_entity="U1", dst_host="C2"),
    ])
    assert inc.high_confidence is False
    assert inc.compound_score < 0.5
    assert inc.sources == {"lanl"}
    assert inc.phases == {"lateral_movement"}


def test_multi_source_multi_phase_is_high_confidence():
    inc = Incident(entity="C553", events=[
        _ev(16, "auth", "lanl", source_entity="U342", dst_host="C553",
            asset_criticality="critical", labels=["redteam"]),
        _ev(19, "process", "otrf", source_entity="U342", src_host="C553",
            dest_entity="cmd /c whoami"),
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17"),
    ])
    assert inc.sources == {"lanl", "otrf", "cicids"}
    assert inc.phases == {"lateral_movement", "discovery", "command_and_control"}
    assert inc.high_confidence is True
    assert inc.is_true_positive is True
    assert inc.compound_score > 0.8
    assert [e.event_type for e in inc.timeline()] == ["auth", "process", "network_flow"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_incident.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.correlate.incident'`

- [ ] **Step 3: Implement**

`apps/api/prahari/correlate/incident.py`:
```python
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from prahari.correlate.killchain import killchain_phase
from prahari.schema import CanonicalEvent

_CRIT_NUM = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0, "unknown": 0.0}
_TRUE_LABELS = {"redteam", "attack"}


@dataclass
class Incident:
    entity: str
    events: list[CanonicalEvent]

    @property
    def start(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def end(self) -> datetime:
        return max(e.timestamp for e in self.events)

    @property
    def phases(self) -> set[str]:
        return {killchain_phase(e) for e in self.events}

    @property
    def sources(self) -> set[str]:
        return {e.source for e in self.events}

    @property
    def is_true_positive(self) -> bool:
        return any(_TRUE_LABELS & set(e.labels) for e in self.events)

    @property
    def _max_criticality(self) -> float:
        return max(_CRIT_NUM.get(e.asset_criticality, 0.0) for e in self.events)

    @property
    def compound_score(self) -> float:
        source_div = min(len(self.sources) - 1, 2) / 2  # 0..1 (2+ sources = max)
        phase_div = min(len(self.phases) - 1, 2) / 2      # 0..1 (3+ phases = max)
        volume = min(len(self.events), 5) / 5             # 0..1 (5+ events = max)
        crit = self._max_criticality
        score = 0.35 * source_div + 0.30 * phase_div + 0.15 * volume + 0.20 * crit
        return round(score, 4)

    @property
    def high_confidence(self) -> bool:
        return len(self.sources) >= 2 and len(self.phases) >= 2

    def timeline(self) -> list[CanonicalEvent]:
        return sorted(self.events, key=lambda e: e.timestamp)
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_incident.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/correlate/incident.py apps/api/tests/test_incident.py
git commit -m "feat(correlate): Incident model with compound scoring"
```

---

### Task 3: Correlator — time-clustered grouping

**Files:**
- Create: `apps/api/prahari/correlate/correlator.py`
- Create: `apps/api/tests/test_correlator.py`

**Interfaces:**
- Consumes: `CanonicalEvent`, `Incident`, `actor_of`, `target_of`.
- Produces:
  - `correlate(events, key_fn, window_seconds) -> list[Incident]` — groups events by `key_fn(event)` (skipping `None` keys); within each group, sorts by time and splits into incidents whenever the gap to the previous event exceeds `window_seconds`. Returns incidents sorted by descending `compound_score`.
  - Re-exports `actor_of`, `target_of` for callers.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_correlator.py`:
```python
from datetime import datetime, timedelta, timezone

from prahari.correlate.correlator import correlate
from prahari.correlate.killchain import actor_of, target_of
from prahari.schema import CanonicalEvent

T0 = datetime(2017, 7, 5, 15, 0, 0, tzinfo=timezone.utc)


def _ev(offset_s, event_type, source, **kw):
    base = dict(timestamp=T0 + timedelta(seconds=offset_s),
                event_type=event_type, source=source, raw="x")
    base.update(kw)
    return CanonicalEvent(**base)


def test_time_gap_splits_incidents():
    events = [
        _ev(0, "auth", "lanl", source_entity="U1", dst_host="C2"),
        _ev(30, "auth", "lanl", source_entity="U1", dst_host="C3"),
        _ev(5000, "auth", "lanl", source_entity="U1", dst_host="C4"),  # far later
    ]
    incs = correlate(events, key_fn=actor_of, window_seconds=300)
    # U1 splits into two incidents: [0,30] and [5000]
    sizes = sorted(len(i.events) for i in incs)
    assert sizes == [1, 2]


def test_fused_timeline_by_target_is_one_high_confidence_incident():
    events = [
        _ev(16, "auth", "lanl", source_entity="U342", dst_host="C553",
            asset_criticality="critical", labels=["redteam"]),
        _ev(19, "process", "otrf", source_entity="U342", src_host="C553",
            dest_entity="cmd /c whoami"),
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17"),
    ]
    incs = correlate(events, key_fn=target_of, window_seconds=300)
    assert len(incs) == 1
    inc = incs[0]
    assert inc.entity == "C553"
    assert inc.high_confidence is True
    assert len(inc.events) == 3
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_correlator.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.correlate.correlator'`

- [ ] **Step 3: Implement**

`apps/api/prahari/correlate/correlator.py`:
```python
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from prahari.correlate.incident import Incident
from prahari.correlate.killchain import actor_of, target_of  # noqa: F401 (re-export)
from prahari.schema import CanonicalEvent


def correlate(
    events: list[CanonicalEvent],
    key_fn: Callable[[CanonicalEvent], str | None],
    window_seconds: float,
) -> list[Incident]:
    groups: dict[str, list[CanonicalEvent]] = defaultdict(list)
    for e in events:
        k = key_fn(e)
        if k is not None:
            groups[k].append(e)

    incidents: list[Incident] = []
    for key, evs in groups.items():
        evs.sort(key=lambda e: e.timestamp)
        cluster = [evs[0]]
        for e in evs[1:]:
            gap = (e.timestamp - cluster[-1].timestamp).total_seconds()
            if gap <= window_seconds:
                cluster.append(e)
            else:
                incidents.append(Incident(entity=key, events=cluster))
                cluster = [e]
        incidents.append(Incident(entity=key, events=cluster))

    incidents.sort(key=lambda i: i.compound_score, reverse=True)
    return incidents
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_correlator.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/correlate/correlator.py apps/api/tests/test_correlator.py
git commit -m "feat(correlate): time-clustered per-entity correlator"
```

---

### Task 4: FP-reduction demonstration (Phase 3 exit gate)

**Files:**
- Create: `apps/api/prahari/correlate/triage.py`
- Create: `apps/api/tests/test_triage.py`

**Interfaces:**
- Consumes: `correlate`, `actor_of`, `Incident`.
- Produces:
  - `triage(flagged_events, window_seconds=600, min_events=3) -> list[Incident]` — actor-correlates flagged events and keeps only incidents with at least `min_events` events (a real intrusion is a burst; scattered false positives are singletons), sorted by `compound_score` desc.
  - Demonstrates that clustering + a burst threshold collapses many per-event flags into few high-value incidents, recovering the true positive while dropping isolated FPs.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_triage.py`:
```python
from datetime import datetime, timedelta, timezone

from prahari.correlate.triage import triage
from prahari.schema import CanonicalEvent

T0 = datetime(2017, 7, 5, 15, 0, 0, tzinfo=timezone.utc)


def _auth(offset_s, user, dst, labels=None):
    return CanonicalEvent(
        timestamp=T0 + timedelta(seconds=offset_s),
        event_type="auth", source_entity=user, src_host="W" + user, dst_host=dst,
        auth_type="NTLM", source="lanl", labels=labels or [], raw="x",
    )


def test_triage_recovers_burst_and_drops_scattered_fps():
    # red-team actor U342: a burst of 4 anomalous lateral moves within window
    flagged = [
        _auth(0, "U342", "C500", labels=["redteam"]),
        _auth(20, "U342", "C501", labels=["redteam"]),
        _auth(40, "U342", "C502", labels=["redteam"]),
        _auth(60, "U342", "C503", labels=["redteam"]),
    ]
    # 15 scattered benign false positives: different users, one stray flag each
    flagged += [_auth(100 + 500 * i, f"B{i}", "C9", labels=[]) for i in range(15)]

    incidents = triage(flagged, window_seconds=600, min_events=3)

    # 19 per-event flags collapse to exactly one surviving incident: the real burst
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.entity == "U342"
    assert inc.is_true_positive is True
    assert len(inc.events) == 4
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_triage.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.correlate.triage'`

- [ ] **Step 3: Implement**

`apps/api/prahari/correlate/triage.py`:
```python
from __future__ import annotations

from prahari.correlate.correlator import correlate
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import actor_of
from prahari.schema import CanonicalEvent


def triage(
    flagged_events: list[CanonicalEvent],
    window_seconds: float = 600,
    min_events: int = 3,
) -> list[Incident]:
    incidents = correlate(flagged_events, key_fn=actor_of, window_seconds=window_seconds)
    kept = [inc for inc in incidents if len(inc.events) >= min_events]
    kept.sort(key=lambda i: i.compound_score, reverse=True)
    return kept
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_triage.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite (Phase 3 Correlator exit gate)**

Run: `cd apps/api && uv run pytest -q`
Expected: PASS — all Phase 1 + 2 + 1.5 + 3(correlator) tests green.

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/correlate/triage.py apps/api/tests/test_triage.py
git commit -m "feat(correlate): actor triage burst filter + Phase 3 correlator exit gate"
```

---

## Self-Review

**Spec coverage (Correlator scope):**
- Compound cross-source fusion into one timeline (spec §3, §6, differentiator #3) → Tasks 2, 3 ✅
- Kill-chain phase tagging (spec §6) → Task 1 ✅
- Compound score fires on ≥2 sources AND ≥2 phases (spec §6) → Task 2 (`high_confidence`) ✅
- The C553 money-moment as one Incident (spec §4) → Task 3 test ✅
- FP reduction (the fix for Phase 1.5's 7.5% FPR) → Task 4 ✅
- Deferred to next plan (correct): Attributor RAG over MITRE via Ollama (`qwen3.5:cloud` confirmed available), Predictor, dashboard rendering of incidents, wiring Sentinel→Correlator on the real LANL slice.

**Placeholder scan:** No TBD/TODO; every code step complete.

**Type consistency:** `killchain_phase`/`actor_of`/`target_of` (Task 1) used by `Incident` (Task 2) and `correlate` (Task 3) and `triage` (Task 4). `Incident(entity, events)` constructor consistent across Tasks 2–4. `correlate(events, key_fn, window_seconds) -> list[Incident]` signature identical in Task 3 impl/test and Task 4 impl. `compound_score`/`high_confidence`/`is_true_positive` property names consistent everywhere.

**Design note:** two grouping views by design — `target_of` builds the victim-centric forensic timeline (C553 story, hero demo); `actor_of` builds the attacker-centric burst used by `triage` for FP reduction. Same correlator, different key function.
