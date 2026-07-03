# Prahari Phase 0+1: Scaffold & Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Prahari monorepo and build the ingestion layer that turns LANL auth, CICIDS netflow, and Sysmon-style process logs into one enriched, time-ordered `CanonicalEvent` stream with red-team labels intact.

**Architecture:** Deterministic ingestion spine. Per-source parsers each map a raw record to a shared Pydantic `CanonicalEvent`. An enrichment pass adds asset criticality + internal/external context. A merge pass time-orders all sources into one list. A replay generator emits the list with compressed real-time pacing (default 100×) so downstream agents and the dashboard see a realistic stream. No ML, no LLM, no network egress in this phase.

**Tech Stack:** Python 3.14 (managed by `uv`), Pydantic v2, FastAPI + uvicorn, pytest, ruff. Next.js (App Router) skeleton + docker-compose for the Phase 0 infra closeout.

## Global Constraints

- Python managed with `uv`; project root for the API is `apps/api`, package name `prahari`.
- Python 3.14 (already installed). Pydantic **v2** syntax only.
- **No raw datasets committed.** Real data lives under `data/raw/` (git-ignored). Tests run only against tiny synthetic fixtures committed under `apps/api/tests/fixtures/`.
- **Sovereign rule:** ingestion code makes **zero network calls**. Download scripts are the only place allowed to touch the network, and they are run manually, never imported by the app.
- All timestamps are timezone-aware UTC `datetime`.
- Every parser sets `raw` to the untouched original record (audit trail).
- Commit after every task with the message shown in its final step.

---

### Task 1: Monorepo scaffold + API package + health endpoint

**Files:**
- Create: `apps/api/pyproject.toml`
- Create: `apps/api/prahari/__init__.py`
- Create: `apps/api/prahari/main.py`
- Create: `apps/api/tests/__init__.py`
- Create: `apps/api/tests/test_health.py`
- Create: `apps/api/tests/fixtures/.gitkeep`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: FastAPI `app` object in `prahari.main`; `pytest` runnable from `apps/api`. Package import root is `prahari`.

- [ ] **Step 1: Create the uv project file**

`apps/api/pyproject.toml`:
```toml
[project]
name = "prahari"
version = "0.1.0"
requires-python = ">=3.14"
dependencies = [
    "fastapi>=0.115",
    "uvicorn>=0.32",
    "pydantic>=2.9",
    "pandas>=2.2",
]

[dependency-groups]
dev = ["pytest>=8.3", "ruff>=0.7", "httpx>=0.27"]

[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]

[tool.ruff]
line-length = 100
```

- [ ] **Step 2: Create the package + a failing health test**

`apps/api/prahari/__init__.py`:
```python
"""Prahari — AI-driven cyber resilience for critical national infrastructure."""
```

`apps/api/tests/__init__.py`: (empty file)

`apps/api/tests/test_health.py`:
```python
from fastapi.testclient import TestClient

from prahari.main import app


def test_health_ok():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "prahari"}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_health.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.main'`

- [ ] **Step 4: Implement the minimal app**

`apps/api/prahari/main.py`:
```python
from fastapi import FastAPI

app = FastAPI(title="Prahari", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "prahari"}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_health.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add apps/api
git commit -m "feat(api): scaffold prahari FastAPI package with health endpoint"
```

---

### Task 2: CanonicalEvent schema

**Files:**
- Create: `apps/api/prahari/schema.py`
- Create: `apps/api/tests/test_schema.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `CanonicalEvent` (Pydantic v2 model) with fields: `timestamp: datetime`, `event_type: Literal["network_flow","auth","process"]`, `source_entity: str|None`, `dest_entity: str|None`, `src_ip: str|None`, `dst_ip: str|None`, `src_host: str|None`, `dst_host: str|None`, `action: str|None`, `outcome: str|None`, `bytes: int|None`, `duration: float|None`, `src_internal: bool|None`, `asset_criticality: Literal["low","medium","high","critical","unknown"]` (default `"unknown"`), `source: str`, `labels: list[str]` (default `[]`), `raw: str`.
  - Type aliases `EventType` and `Criticality`.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_schema.py`:
```python
from datetime import datetime, timezone

from prahari.schema import CanonicalEvent


def test_minimal_event_defaults():
    ev = CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, 16, tzinfo=timezone.utc),
        event_type="auth",
        source="lanl",
        raw="151036,U342@DOM1,...",
    )
    assert ev.asset_criticality == "unknown"
    assert ev.labels == []
    assert ev.src_ip is None
    assert ev.raw.startswith("151036")


def test_labels_are_independent_per_instance():
    a = CanonicalEvent(timestamp=datetime.now(timezone.utc), event_type="auth", source="lanl", raw="x")
    b = CanonicalEvent(timestamp=datetime.now(timezone.utc), event_type="auth", source="lanl", raw="y")
    a.labels.append("redteam")
    assert b.labels == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_schema.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.schema'`

- [ ] **Step 3: Implement the schema**

`apps/api/prahari/schema.py`:
```python
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

EventType = Literal["network_flow", "auth", "process"]
Criticality = Literal["low", "medium", "high", "critical", "unknown"]


class CanonicalEvent(BaseModel):
    timestamp: datetime
    event_type: EventType
    source_entity: str | None = None
    dest_entity: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_host: str | None = None
    dst_host: str | None = None
    action: str | None = None
    outcome: str | None = None
    bytes: int | None = None
    duration: float | None = None
    src_internal: bool | None = None
    asset_criticality: Criticality = "unknown"
    source: str
    labels: list[str] = Field(default_factory=list)
    raw: str
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_schema.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/schema.py apps/api/tests/test_schema.py
git commit -m "feat(schema): add CanonicalEvent common event model"
```

---

### Task 3: LANL auth parser with red-team labeling

**Files:**
- Create: `apps/api/prahari/parsers/__init__.py`
- Create: `apps/api/prahari/parsers/lanl.py`
- Create: `apps/api/tests/fixtures/lanl_auth_sample.txt`
- Create: `apps/api/tests/fixtures/lanl_redteam_sample.txt`
- Create: `apps/api/tests/test_lanl.py`

**Interfaces:**
- Consumes: `CanonicalEvent` from `prahari.schema`.
- Produces:
  - `load_redteam(path: str | Path) -> set[tuple[str, str, str, str]]` — keys are `(time, user, src_comp, dst_comp)` strings.
  - `parse_lanl_line(line: str, redteam: set[tuple[str, str, str, str]]) -> CanonicalEvent`.
  - `parse_lanl_file(auth_path, redteam_path) -> Iterator[CanonicalEvent]`.
  - Module constant `LANL_EPOCH` (UTC anchor `datetime(2017, 1, 1, tzinfo=UTC)`); LANL times are relative seconds added to this.

- [ ] **Step 1: Create fixtures**

`apps/api/tests/fixtures/lanl_auth_sample.txt` (LANL `auth.txt` columns: `time,src_user,dst_user,src_comp,dst_comp,auth_type,logon_type,auth_orientation,success`):
```
151016,U100@DOM1,U100@DOM1,C1115,C1115,Kerberos,Network,LogOn,Success
151036,U342@DOM1,U342@DOM1,C1115,C553,NTLM,Network,LogOn,Success
151040,U100@DOM1,U100@DOM1,C1115,C988,Kerberos,Network,LogOn,Success
```

`apps/api/tests/fixtures/lanl_redteam_sample.txt` (LANL `redteam.txt` columns: `time,user,src_comp,dst_comp`):
```
151036,U342@DOM1,C1115,C553
```

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_lanl.py`:
```python
from pathlib import Path

from prahari.parsers.lanl import load_redteam, parse_lanl_file

FIX = Path(__file__).parent / "fixtures"


def test_lanl_parses_and_labels_redteam():
    redteam = load_redteam(FIX / "lanl_redteam_sample.txt")
    events = list(parse_lanl_file(FIX / "lanl_auth_sample.txt", FIX / "lanl_redteam_sample.txt"))

    assert len(events) == 3
    assert all(e.event_type == "auth" and e.source == "lanl" for e in events)

    flagged = [e for e in events if "redteam" in e.labels]
    assert len(flagged) == 1
    e = flagged[0]
    assert e.source_entity == "U342@DOM1"
    assert e.src_host == "C1115"
    assert e.dst_host == "C553"
    assert e.action == "login"
    assert e.outcome == "success"
    assert e.raw.startswith("151036,U342@DOM1")
    # ("151036","U342@DOM1","C1115","C553") is in the redteam set
    assert ("151036", "U342@DOM1", "C1115", "C553") in redteam
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_lanl.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.parsers'`

- [ ] **Step 4: Implement the parser**

`apps/api/prahari/parsers/__init__.py`: (empty file)

`apps/api/prahari/parsers/lanl.py`:
```python
from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from prahari.schema import CanonicalEvent

# LANL times are integer seconds relative to the capture start.
# Anchor to an arbitrary UTC epoch so downstream code gets real datetimes.
LANL_EPOCH = datetime(2017, 1, 1, tzinfo=timezone.utc)

RedteamKey = tuple[str, str, str, str]


def load_redteam(path: str | Path) -> set[RedteamKey]:
    keys: set[RedteamKey] = set()
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        t, user, src, dst = line.split(",")
        keys.add((t, user, src, dst))
    return keys


def parse_lanl_line(line: str, redteam: set[RedteamKey]) -> CanonicalEvent:
    t, su, du, sc, dc, atype, ltype, orient, success = line.split(",")
    key: RedteamKey = (t, su, sc, dc)
    labels = ["redteam"] if key in redteam else []
    ts = LANL_EPOCH + timedelta(seconds=int(t))
    return CanonicalEvent(
        timestamp=ts,
        event_type="auth",
        source_entity=su,
        dest_entity=du,
        src_host=sc,
        dst_host=dc,
        action="login",
        outcome=success.lower(),
        source="lanl",
        labels=labels,
        raw=line,
    )


def parse_lanl_file(
    auth_path: str | Path, redteam_path: str | Path
) -> Iterator[CanonicalEvent]:
    redteam = load_redteam(redteam_path)
    for line in Path(auth_path).read_text().splitlines():
        if line.strip():
            yield parse_lanl_line(line, redteam)
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_lanl.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/parsers apps/api/tests/test_lanl.py apps/api/tests/fixtures/lanl_auth_sample.txt apps/api/tests/fixtures/lanl_redteam_sample.txt
git commit -m "feat(parsers): LANL auth parser with red-team labeling"
```

---

### Task 4: CICIDS netflow parser

**Files:**
- Create: `apps/api/prahari/parsers/cicids.py`
- Create: `apps/api/tests/fixtures/cicids_sample.csv`
- Create: `apps/api/tests/test_cicids.py`

**Interfaces:**
- Consumes: `CanonicalEvent` from `prahari.schema`.
- Produces:
  - `parse_cicids_row(row: dict) -> CanonicalEvent`.
  - `parse_cicids_file(path: str | Path) -> Iterator[CanonicalEvent]` (reads CSV via pandas, yields events).
  - Benign rows (`Label == "BENIGN"`) get `labels == []`; attack rows get `["attack", <label>]`.

- [ ] **Step 1: Create fixture**

`apps/api/tests/fixtures/cicids_sample.csv`:
```
Timestamp,Source IP,Destination IP,Total Length of Fwd Packets,Flow Duration,Label
5/7/2017 15:32,192.168.10.5,52.84.23.17,220,1183,BENIGN
5/7/2017 15:32,10.0.0.9,52.84.23.17,54000,900000,DDoS
```

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_cicids.py`:
```python
from pathlib import Path

from prahari.parsers.cicids import parse_cicids_file

FIX = Path(__file__).parent / "fixtures"


def test_cicids_parses_flows_and_labels_attacks():
    events = list(parse_cicids_file(FIX / "cicids_sample.csv"))
    assert len(events) == 2
    assert all(e.event_type == "network_flow" and e.source == "cicids" for e in events)

    benign = events[0]
    assert benign.labels == []
    assert benign.src_ip == "192.168.10.5"
    assert benign.dst_ip == "52.84.23.17"
    assert benign.bytes == 220
    assert benign.action == "connect"

    attack = events[1]
    assert attack.labels == ["attack", "DDoS"]
    assert attack.bytes == 54000
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_cicids.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.parsers.cicids'`

- [ ] **Step 4: Implement the parser**

`apps/api/prahari/parsers/cicids.py`:
```python
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pandas as pd

from prahari.schema import CanonicalEvent


def _to_int(value) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _to_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_cicids_row(row: dict) -> CanonicalEvent:
    label = str(row.get("Label", "BENIGN")).strip()
    labels = [] if label.upper() == "BENIGN" else ["attack", label]
    ts = pd.to_datetime(row["Timestamp"]).to_pydatetime()
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=__import__("datetime").timezone.utc)
    return CanonicalEvent(
        timestamp=ts,
        event_type="network_flow",
        src_ip=(str(row["Source IP"]) if row.get("Source IP") is not None else None),
        dst_ip=(str(row["Destination IP"]) if row.get("Destination IP") is not None else None),
        action="connect",
        bytes=_to_int(row.get("Total Length of Fwd Packets")),
        duration=_to_float(row.get("Flow Duration")),
        source="cicids",
        labels=labels,
        raw=",".join(str(v) for v in row.values()),
    )


def parse_cicids_file(path: str | Path) -> Iterator[CanonicalEvent]:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    for record in df.to_dict(orient="records"):
        yield parse_cicids_row(record)
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_cicids.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/parsers/cicids.py apps/api/tests/test_cicids.py apps/api/tests/fixtures/cicids_sample.csv
git commit -m "feat(parsers): CICIDS netflow parser"
```

---

### Task 5: Sysmon-style process parser

**Files:**
- Create: `apps/api/prahari/parsers/process.py`
- Create: `apps/api/tests/fixtures/sysmon_sample.jsonl`
- Create: `apps/api/tests/test_process.py`

**Interfaces:**
- Consumes: `CanonicalEvent` from `prahari.schema`.
- Produces:
  - `parse_sysmon_obj(obj: dict) -> CanonicalEvent`.
  - `parse_sysmon_file(path: str | Path) -> Iterator[CanonicalEvent]` (reads JSON-lines).
  - Expects each object to carry ISO-8601 `UtcTime`, plus `User`, `Computer`, `Image`, `CommandLine`, optional `_labels: list[str]`.
  - `action` is `"execute"`; the executed command is stored in `dest_entity` (the command line), so the timeline can show `execute cmd "whoami"`.

- [ ] **Step 1: Create fixture**

`apps/api/tests/fixtures/sysmon_sample.jsonl`:
```
{"UtcTime": "2017-07-05T15:32:19+00:00", "User": "U342@DOM1", "Computer": "C553", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami", "_labels": ["redteam"]}
{"UtcTime": "2017-07-05T15:31:00+00:00", "User": "U100@DOM1", "Computer": "C1115", "Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe"}
```

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_process.py`:
```python
from pathlib import Path

from prahari.parsers.process import parse_sysmon_file

FIX = Path(__file__).parent / "fixtures"


def test_sysmon_parses_process_events():
    events = list(parse_sysmon_file(FIX / "sysmon_sample.jsonl"))
    assert len(events) == 2
    assert all(e.event_type == "process" and e.source == "sysmon" for e in events)

    redteam = [e for e in events if "redteam" in e.labels]
    assert len(redteam) == 1
    e = redteam[0]
    assert e.source_entity == "U342@DOM1"
    assert e.src_host == "C553"
    assert e.action == "execute"
    assert "whoami" in e.dest_entity
    assert e.timestamp.year == 2017
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_process.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.parsers.process'`

- [ ] **Step 4: Implement the parser**

`apps/api/prahari/parsers/process.py`:
```python
from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from prahari.schema import CanonicalEvent


def parse_sysmon_obj(obj: dict) -> CanonicalEvent:
    ts = datetime.fromisoformat(obj["UtcTime"])
    return CanonicalEvent(
        timestamp=ts,
        event_type="process",
        source_entity=obj.get("User"),
        dest_entity=obj.get("CommandLine") or obj.get("Image"),
        src_host=obj.get("Computer"),
        action="execute",
        outcome="success",
        source="sysmon",
        labels=list(obj.get("_labels", [])),
        raw=json.dumps(obj, sort_keys=True),
    )


def parse_sysmon_file(path: str | Path) -> Iterator[CanonicalEvent]:
    for line in Path(path).read_text().splitlines():
        if line.strip():
            yield parse_sysmon_obj(json.loads(line))
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_process.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/parsers/process.py apps/api/tests/test_process.py apps/api/tests/fixtures/sysmon_sample.jsonl
git commit -m "feat(parsers): Sysmon-style process parser"
```

---

### Task 6: Enrichment layer

**Files:**
- Create: `apps/api/prahari/enrich.py`
- Create: `apps/api/tests/test_enrich.py`

**Interfaces:**
- Consumes: `CanonicalEvent`, `Criticality` from `prahari.schema`.
- Produces:
  - `ASSET_CRITICALITY: dict[str, Criticality]` demo lookup (includes `"C553": "critical"`, `"C1115": "medium"`).
  - `is_internal(ip: str | None) -> bool | None` (RFC1918 prefixes → True, None passthrough).
  - `enrich(ev: CanonicalEvent) -> CanonicalEvent` — mutates and returns the same instance. Sets `asset_criticality` from the destination host (falling back to source host), and `src_internal` from `src_ip`.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_enrich.py`:
```python
from datetime import datetime, timezone

from prahari.enrich import enrich, is_internal
from prahari.schema import CanonicalEvent


def _auth(dst_host, src_ip=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, tzinfo=timezone.utc),
        event_type="auth",
        dst_host=dst_host,
        src_ip=src_ip,
        source="lanl",
        raw="x",
    )


def test_is_internal():
    assert is_internal("10.0.0.9") is True
    assert is_internal("192.168.1.1") is True
    assert is_internal("52.84.23.17") is False
    assert is_internal(None) is None


def test_enrich_sets_criticality_and_internal():
    ev = enrich(_auth("C553", src_ip="10.0.0.9"))
    assert ev.asset_criticality == "critical"
    assert ev.src_internal is True


def test_enrich_unknown_host_stays_unknown():
    ev = enrich(_auth("C9999"))
    assert ev.asset_criticality == "unknown"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_enrich.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.enrich'`

- [ ] **Step 3: Implement enrichment**

`apps/api/prahari/enrich.py`:
```python
from __future__ import annotations

from prahari.schema import CanonicalEvent, Criticality

# Demo asset criticality table. In production this is a CMDB lookup.
ASSET_CRITICALITY: dict[str, Criticality] = {
    "C553": "critical",
    "C1115": "medium",
    "C988": "low",
}

_INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.")


def is_internal(ip: str | None) -> bool | None:
    if ip is None:
        return None
    return ip.startswith(_INTERNAL_PREFIXES)


def enrich(ev: CanonicalEvent) -> CanonicalEvent:
    host = ev.dst_host or ev.src_host
    if host and host in ASSET_CRITICALITY:
        ev.asset_criticality = ASSET_CRITICALITY[host]
    if ev.src_ip is not None:
        ev.src_internal = is_internal(ev.src_ip)
    return ev
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_enrich.py -v`
Expected: PASS (all three tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/enrich.py apps/api/tests/test_enrich.py
git commit -m "feat(enrich): asset criticality + internal/external enrichment"
```

---

### Task 7: Merge + time-order

**Files:**
- Create: `apps/api/prahari/stream.py`
- Create: `apps/api/tests/test_stream.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces: `merge_ordered(*streams: Iterable[CanonicalEvent]) -> list[CanonicalEvent]` — flattens all inputs, returns a new list sorted ascending by `timestamp` (stable sort preserves input order for equal timestamps).

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_stream.py`:
```python
from datetime import datetime, timezone

from prahari.schema import CanonicalEvent
from prahari.stream import merge_ordered


def _ev(sec, source):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, sec, tzinfo=timezone.utc),
        event_type="auth",
        source=source,
        raw=f"{source}-{sec}",
    )


def test_merge_orders_by_timestamp_across_sources():
    a = [_ev(24, "cicids"), _ev(16, "lanl")]
    b = [_ev(19, "sysmon")]
    merged = merge_ordered(a, b)
    assert [e.timestamp.second for e in merged] == [16, 19, 24]
    assert [e.source for e in merged] == ["lanl", "sysmon", "cicids"]


def test_merge_empty():
    assert merge_ordered([], []) == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_stream.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.stream'`

- [ ] **Step 3: Implement merge**

`apps/api/prahari/stream.py`:
```python
from __future__ import annotations

from collections.abc import Iterable

from prahari.schema import CanonicalEvent


def merge_ordered(*streams: Iterable[CanonicalEvent]) -> list[CanonicalEvent]:
    events = [e for stream in streams for e in stream]
    events.sort(key=lambda e: e.timestamp)  # stable
    return events
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_stream.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/stream.py apps/api/tests/test_stream.py
git commit -m "feat(stream): time-order merge across sources"
```

---

### Task 8: Replay engine (time-compressed)

**Files:**
- Create: `apps/api/prahari/replay.py`
- Create: `apps/api/tests/test_replay.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces: `replay(events: list[CanonicalEvent], speed: float = 100.0, sleep: Callable[[float], None] = time.sleep) -> Iterator[CanonicalEvent]`. Emits events in order; between consecutive events it calls `sleep(gap_seconds / speed)` where `gap_seconds` is the wall gap between their timestamps. `sleep` is injectable so tests run instantly and assert the pacing schedule.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_replay.py`:
```python
from datetime import datetime, timezone

from prahari.replay import replay
from prahari.schema import CanonicalEvent


def _ev(sec):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, sec, tzinfo=timezone.utc),
        event_type="auth",
        source="lanl",
        raw=str(sec),
    )


def test_replay_yields_in_order_and_paces_by_speed():
    events = [_ev(0), _ev(10), _ev(40)]  # gaps 10s, 30s
    slept: list[float] = []
    out = list(replay(events, speed=100.0, sleep=slept.append))

    assert [e.timestamp.second for e in out] == [0, 10, 40]
    # first event no sleep; then 10/100 and 30/100
    assert slept == [0.1, 0.3]


def test_replay_empty():
    assert list(replay([], sleep=lambda _s: None)) == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_replay.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.replay'`

- [ ] **Step 3: Implement replay**

`apps/api/prahari/replay.py`:
```python
from __future__ import annotations

import time
from collections.abc import Callable, Iterator

from prahari.schema import CanonicalEvent


def replay(
    events: list[CanonicalEvent],
    speed: float = 100.0,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[CanonicalEvent]:
    prev = None
    for ev in events:
        if prev is not None:
            gap = (ev.timestamp - prev).total_seconds() / speed
            if gap > 0:
                sleep(gap)
        prev = ev.timestamp
        yield ev
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_replay.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/replay.py apps/api/tests/test_replay.py
git commit -m "feat(replay): time-compressed event replay generator"
```

---

### Task 9: Ingestion orchestration + Phase 1 exit test

**Files:**
- Create: `apps/api/prahari/ingest.py`
- Create: `apps/api/tests/test_ingest_e2e.py`
- Create: `data/README.md`
- Create: `data/download.sh`

**Interfaces:**
- Consumes: all parsers, `enrich`, `merge_ordered`.
- Produces:
  - `load_all(lanl_auth, lanl_redteam, cicids, sysmon) -> list[CanonicalEvent]` — parses each present source, enriches every event, returns the time-ordered merged list. Any argument may be `None` to skip that source.
  - This is the Phase 1 deliverable: one enriched, ordered stream with labels intact.

- [ ] **Step 1: Write the failing end-to-end test**

`apps/api/tests/test_ingest_e2e.py`:
```python
from pathlib import Path

from prahari.ingest import load_all

FIX = Path(__file__).parent / "fixtures"


def test_load_all_produces_ordered_enriched_labeled_stream():
    events = load_all(
        lanl_auth=FIX / "lanl_auth_sample.txt",
        lanl_redteam=FIX / "lanl_redteam_sample.txt",
        cicids=FIX / "cicids_sample.csv",
        sysmon=FIX / "sysmon_sample.jsonl",
    )
    # 3 LANL + 2 CICIDS + 2 sysmon
    assert len(events) == 7

    # ordered by timestamp
    ts = [e.timestamp for e in events]
    assert ts == sorted(ts)

    # red-team labels survived ingestion (LANL auth + sysmon process)
    redteam = [e for e in events if "redteam" in e.labels]
    assert len(redteam) == 2
    assert {e.event_type for e in redteam} == {"auth", "process"}

    # enrichment ran: the C553 critical asset is tagged
    c553 = [e for e in events if e.dst_host == "C553" or e.src_host == "C553"]
    assert any(e.asset_criticality == "critical" for e in c553)


def test_load_all_skips_missing_sources():
    events = load_all(
        lanl_auth=FIX / "lanl_auth_sample.txt",
        lanl_redteam=FIX / "lanl_redteam_sample.txt",
        cicids=None,
        sysmon=None,
    )
    assert len(events) == 3
    assert all(e.source == "lanl" for e in events)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_ingest_e2e.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.ingest'`

- [ ] **Step 3: Implement the orchestration**

`apps/api/prahari/ingest.py`:
```python
from __future__ import annotations

from pathlib import Path

from prahari.enrich import enrich
from prahari.parsers.cicids import parse_cicids_file
from prahari.parsers.lanl import parse_lanl_file
from prahari.parsers.process import parse_sysmon_file
from prahari.schema import CanonicalEvent
from prahari.stream import merge_ordered


def load_all(
    lanl_auth: str | Path | None = None,
    lanl_redteam: str | Path | None = None,
    cicids: str | Path | None = None,
    sysmon: str | Path | None = None,
) -> list[CanonicalEvent]:
    streams: list[list[CanonicalEvent]] = []
    if lanl_auth is not None and lanl_redteam is not None:
        streams.append(list(parse_lanl_file(lanl_auth, lanl_redteam)))
    if cicids is not None:
        streams.append(list(parse_cicids_file(cicids)))
    if sysmon is not None:
        streams.append(list(parse_sysmon_file(sysmon)))

    merged = merge_ordered(*streams)
    return [enrich(ev) for ev in merged]
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_ingest_e2e.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Run the full suite (Phase 1 exit gate)**

Run: `cd apps/api && uv run pytest -v`
Expected: PASS — all tests green (health, schema, 3 parsers, enrich, stream, replay, e2e).

- [ ] **Step 6: Write the dataset download docs/scripts (manual, network-isolated from the app)**

`data/README.md`:
```markdown
# Datasets (not committed)

Real data lands in `data/raw/` (git-ignored). The app never downloads — only these scripts do.

| Dataset | File(s) | Source |
|---|---|---|
| LANL Auth | `auth.txt`, `redteam.txt` | https://csr.lanl.gov/data/cyber1/ |
| CICIDS2017 | `*.csv` | https://www.unb.ca/cic/datasets/ids-2017.html |
| OTRF Security-Datasets (Sysmon) | `*.jsonl` | https://github.com/OTRF/Security-Datasets |

Run `bash data/download.sh` after placing credentials/accepting dataset terms.
```

`data/download.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
mkdir -p data/raw
echo "Place LANL auth.txt + redteam.txt, CICIDS csv, and OTRF jsonl into data/raw/."
echo "These datasets require accepting their terms; download manually from the URLs in data/README.md."
```

- [ ] **Step 7: Commit**

```bash
git add apps/api/prahari/ingest.py apps/api/tests/test_ingest_e2e.py data/README.md data/download.sh
git commit -m "feat(ingest): unified enriched time-ordered stream + Phase 1 exit test"
```

---

### Task 10: Phase 0 infra closeout — Next.js skeleton + docker-compose

**Files:**
- Create: `apps/web/package.json`
- Create: `apps/web/app/page.tsx`
- Create: `apps/web/app/layout.tsx`
- Create: `apps/web/next.config.mjs`
- Create: `apps/web/tsconfig.json`
- Create: `docker-compose.yml`
- Create: `README.md`

**Interfaces:**
- Consumes: nothing at runtime (skeleton).
- Produces: `docker-compose up` brings the stack online; `apps/web` renders a placeholder SOC landing page; Ollama + Chroma services are declared for later phases. This closes the Phase 0 exit test.

- [ ] **Step 1: Create the Next.js skeleton**

`apps/web/package.json`:
```json
{
  "name": "prahari-web",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "next dev -p 3000",
    "build": "next build",
    "start": "next start -p 3000"
  },
  "dependencies": {
    "next": "^15.0.0",
    "react": "^19.0.0",
    "react-dom": "^19.0.0"
  },
  "devDependencies": {
    "typescript": "^5.6.0",
    "@types/react": "^19.0.0",
    "@types/node": "^22.0.0"
  }
}
```

`apps/web/next.config.mjs`:
```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {};
export default nextConfig;
```

`apps/web/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["dom", "dom.iterable", "esnext"],
    "jsx": "preserve",
    "module": "esnext",
    "moduleResolution": "bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "plugins": [{ "name": "next" }]
  },
  "include": ["**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
```

`apps/web/app/layout.tsx`:
```tsx
export const metadata = { title: "Prahari SOC", description: "Cyber resilience command center" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ background: "#0a0e14", color: "#e6edf3", fontFamily: "monospace", margin: 0 }}>
        {children}
      </body>
    </html>
  );
}
```

`apps/web/app/page.tsx`:
```tsx
export default function Home() {
  return (
    <main style={{ padding: "3rem" }}>
      <h1>प्रहरी · Prahari</h1>
      <p>Cyber Resilience Command Center — scaffold online.</p>
    </main>
  );
}
```

- [ ] **Step 2: Create docker-compose for the stack**

`docker-compose.yml`:
```yaml
services:
  api:
    build: ./apps/api
    working_dir: /app
    command: uv run uvicorn prahari.main:app --host 0.0.0.0 --port 8000
    ports:
      - "8000:8000"
    environment:
      - SOVEREIGN_MODE=true

  web:
    build: ./apps/web
    ports:
      - "3000:3000"
    depends_on:
      - api

  chroma:
    image: chromadb/chroma:latest
    ports:
      - "8001:8000"
    volumes:
      - ./chroma:/chroma/chroma

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ./ollama:/root/.ollama
```

- [ ] **Step 3: Create the top-level README**

`README.md`:
```markdown
# Prahari — AI-Driven Cyber Resilience for Critical National Infrastructure

ET AI Hackathon 2026 · Problem Statement 7. Behavioural (not signature) threat
detection that fuses auth + network + endpoint telemetry into one incident
timeline, maps it to MITRE ATT&CK with cited reasoning, and runs fully
air-gapped.

## Layout
- `apps/api` — FastAPI: ingestion, agents, replay (Python 3.14 + uv)
- `apps/web` — Next.js SOC command dashboard
- `data/`   — dataset download scripts (raw data git-ignored)
- `docs/superpowers/` — specs and plans

## Dev
- API tests: `cd apps/api && uv run pytest -v`
- Full stack: `docker-compose up`

See `docs/superpowers/specs/2026-07-03-prahari-cyber-resilience-design.md`.
```

- [ ] **Step 4: Verify the API test suite still passes (regression gate)**

Run: `cd apps/api && uv run pytest -v`
Expected: PASS — all tests still green.

- [ ] **Step 5: Commit**

```bash
git add apps/web docker-compose.yml README.md
git commit -m "chore(infra): Next.js skeleton + docker-compose stack (Phase 0 closeout)"
```

---

## Self-Review

**Spec coverage (Phase 0+1 scope):**
- Monorepo shape (spec §14) → Tasks 1, 10 ✅
- Common event schema (spec §4) → Task 2 ✅
- LANL parser + red-team labeling (spec §11) → Task 3 ✅
- CICIDS parser (spec §11) → Task 4 ✅
- Sysmon/process parser (spec §11) → Task 5 ✅
- Enrichment: criticality + internal/external (spec §3 spine) → Task 6 ✅
- Time-align/merge (spec §3) → Task 7 ✅
- Replay engine, ~100× compression (spec §13) → Task 8 ✅
- Phase 1 exit test: unified ordered stream, labels intact (spec §19) → Task 9 ✅
- docker-compose + sovereign env flag (spec §15) → Task 10 ✅
- Deferred to later plans (correct): Sentinel/ML, Correlator, Attributor/RAG, Predictor, Responder, dashboard screens, metrics harness, CERT-In scrape.

**Placeholder scan:** No TBD/TODO; every code step shows complete code. `data/download.sh` intentionally prints manual instructions (datasets require accepting terms) — not a code placeholder.

**Type consistency:** `CanonicalEvent` fields used identically across all parsers, enrich, stream, replay, ingest. `parse_lanl_file(auth, redteam)`, `parse_cicids_file(path)`, `parse_sysmon_file(path)`, `enrich(ev)`, `merge_ordered(*streams)`, `replay(events, speed, sleep)`, `load_all(...)` signatures match every call site. Red-team key tuple `(time, user, src, dst)` consistent between Task 3 fixture, `load_redteam`, and `parse_lanl_line`.

**Note on real data vs fixtures:** Tasks build and test against synthetic fixtures. When real LANL/CICIDS/OTRF data is dropped into `data/raw/`, `load_all` takes those paths unchanged — column-name drift in real CICIDS CSVs is the one likely friction point (handled by the `df.columns.strip()` + `.get()` defensive reads in Task 4).
