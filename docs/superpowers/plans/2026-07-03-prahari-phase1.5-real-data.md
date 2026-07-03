# Prahari Phase 1.5: Wire Real Datasets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adapt the synthetic-fixture parsers/detectors to the real LANL, CICIDS2017, and OTRF datasets and produce a real benchmark — Sentinel vs signature precision/recall/FPR on genuine LANL red-team lateral movement.

**Architecture:** Add batch scoring to the detectors (single-event scoring can't handle millions of rows), a streaming LANL window slicer (auth.txt is 7.2G, time-sorted → stream-and-stop), real-format CICIDS + OTRF adapters, and a benchmark runner. Unit tests run against tiny committed real-format fixtures; the real multi-GB run is a documented manual step.

**Tech Stack:** Python 3.14 + uv, numpy, scikit-learn, pandas. Builds on Phase 1 (`CanonicalEvent`, parsers, enrich) and Phase 2 (`Sentinel`, `NetworkSentinel`, `SignatureBaseline`, metrics).

## Global Constraints

- Package root `apps/api`, package `prahari`; tests: `cd apps/api && uv run pytest`.
- **No raw data in git** (`data/*` is ignored). Tests use only tiny fixtures under `apps/api/tests/fixtures/`.
- Real dataset formats (verified 2026-07-03):
  - LANL `auth.txt`: `time,src_user,dst_user,src_comp,dst_comp,auth_type,logon_type,orientation,success`; `auth_type` may be `?`.
  - LANL `redteam.txt`: `time,user,src_comp,dst_comp` (749 events, times 150885–2557047).
  - CICIDS MachineLearningCVE CSV: flow features + trailing `Label`, **no** IP/Timestamp, column names have leading spaces.
  - OTRF Sysmon JSON: host=`Hostname`, tz-aware `@timestamp`, `User`=`DOMAIN\user`, process-create is `EventID==1`, `CommandLine` present.
- Anomaly-score convention unchanged: higher = more anomalous.
- Batch methods must return `numpy.ndarray` aligned with the input list order.
- Commit after every task with the message in its final step.

---

### Task 1: Batch scoring for Sentinel and NetworkSentinel

**Files:**
- Modify: `apps/api/prahari/detect/sentinel.py`
- Modify: `apps/api/prahari/detect/network.py`
- Create: `apps/api/tests/test_batch_scoring.py`

**Interfaces:**
- Consumes: existing `Sentinel`, `NetworkSentinel`.
- Produces:
  - `Sentinel.anomaly_scores(events: list[CanonicalEvent]) -> np.ndarray` — vectorised; equals `[anomaly_score(e) for e in events]` but one `score_samples` call.
  - `NetworkSentinel.anomaly_scores(events: list[CanonicalEvent]) -> np.ndarray` — same contract.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_batch_scoring.py`:
```python
from datetime import datetime, timezone

import numpy as np

from prahari.detect.network import NetworkSentinel
from prahari.detect.sentinel import Sentinel
from prahari.schema import CanonicalEvent


def _auth(user, src, dst, atype, hour, crit="unknown"):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, hour, tzinfo=timezone.utc),
        event_type="auth", source_entity=user, src_host=src, dst_host=dst,
        auth_type=atype, asset_criticality=crit, source="lanl", raw="x",
    )


def _flow(nbytes, duration):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, tzinfo=timezone.utc),
        event_type="network_flow", bytes=nbytes, duration=duration, source="cicids", raw="x",
    )


def test_sentinel_batch_matches_single():
    train = [_auth("U100", "C1", "C2", "Kerberos", 15) for _ in range(20)]
    s = Sentinel(random_state=0).fit(train)
    probe = train + [_auth("U100", "C1", "C553", "NTLM", 3, crit="critical")]
    single = np.array([s.anomaly_score(e) for e in probe])
    batch = s.anomaly_scores(probe)
    assert np.allclose(single, batch)


def test_network_batch_matches_single():
    rng = np.random.default_rng(0)
    train = [_flow(int(b), float(d)) for b, d in zip(rng.normal(220, 15, 50), rng.normal(1100, 80, 50))]
    n = NetworkSentinel(random_state=0).fit(train)
    probe = train + [_flow(54000, 900000)]
    single = np.array([n.anomaly_score(e) for e in probe])
    batch = n.anomaly_scores(probe)
    assert np.allclose(single, batch)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_batch_scoring.py -v`
Expected: FAIL — `AttributeError: 'Sentinel' object has no attribute 'anomaly_scores'`

- [ ] **Step 3: Add batch scoring to Sentinel**

In `apps/api/prahari/detect/sentinel.py`, add this method to `Sentinel` (after `anomaly_score`):
```python
    def anomaly_scores(self, events: list[CanonicalEvent]) -> np.ndarray:
        if not events:
            return np.empty(0, dtype=float)
        x = np.array([self.baseline.featurize(e) for e in events], dtype=float)
        novelty = x @ _WEIGHTS
        raw = -self.model.score_samples(x)
        rng = self._if_max - self._if_min
        if rng > 0:
            if_norm = np.clip((raw - self._if_min) / rng, 0.0, 1.0)
        else:
            if_norm = np.zeros(len(events), dtype=float)
        return self.novelty_weight * novelty + (1.0 - self.novelty_weight) * if_norm
```

- [ ] **Step 4: Add batch scoring to NetworkSentinel**

In `apps/api/prahari/detect/network.py`, add this method to `NetworkSentinel` (after `anomaly_score`):
```python
    def anomaly_scores(self, events: list[CanonicalEvent]) -> np.ndarray:
        if not events:
            return np.empty(0, dtype=float)
        x = np.array([_features(e) for e in events], dtype=float)
        xs = self.scaler.transform(x)
        return -self.model.score_samples(xs)
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_batch_scoring.py -v`
Expected: PASS (both tests)

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/detect/sentinel.py apps/api/prahari/detect/network.py apps/api/tests/test_batch_scoring.py
git commit -m "feat(detect): vectorised batch anomaly scoring"
```

---

### Task 2: LANL window slicer

**Files:**
- Create: `apps/api/prahari/data/__init__.py`
- Create: `apps/api/prahari/data/lanl_slice.py`
- Create: `apps/api/tests/test_lanl_slice.py`

**Interfaces:**
- Consumes: `parse_lanl_line`, `load_redteam` semantics (red-team key = `(time, src_user, src_comp, dst_comp)`).
- Produces:
  - `slice_auth_lines(lines: Iterable[str], t0: int, t1: int) -> Iterator[str]` — yields raw auth lines whose leading integer time is in `[t0, t1)`. Pure/streamable (no gzip dependency), stops iterating input once `time >= t1`.
  - `redteam_in_window(redteam: set[tuple[str,str,str,str]], t0: int, t1: int) -> set[...]` — the subset whose time is in `[t0, t1)`.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_lanl_slice.py`:
```python
from prahari.data.lanl_slice import redteam_in_window, slice_auth_lines


def test_slice_auth_lines_keeps_window_and_stops_early():
    lines = [
        "100,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success",
        "200,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success",
        "300,U2@D,U2@D,C3,C4,NTLM,Network,LogOn,Success",
        "400,U2@D,U2@D,C3,C4,NTLM,Network,LogOn,Success",
    ]
    out = list(slice_auth_lines(iter(lines), t0=200, t1=400))
    # keeps times 200 and 300; 400 is excluded (half-open) and stops there
    assert [ln.split(",")[0] for ln in out] == ["200", "300"]


def test_redteam_in_window():
    rt = {("150", "U1@D", "C1", "C2"), ("500", "U9@D", "C8", "C9")}
    assert redteam_in_window(rt, 100, 300) == {("150", "U1@D", "C1", "C2")}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_lanl_slice.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.data'`

- [ ] **Step 3: Implement the slicer**

`apps/api/prahari/data/__init__.py`: (empty file)

`apps/api/prahari/data/lanl_slice.py`:
```python
from __future__ import annotations

from collections.abc import Iterable, Iterator

RedteamKey = tuple[str, str, str, str]


def slice_auth_lines(lines: Iterable[str], t0: int, t1: int) -> Iterator[str]:
    for line in lines:
        idx = line.find(",")
        if idx < 0:
            continue
        try:
            t = int(line[:idx])
        except ValueError:
            continue
        if t >= t1:
            return  # auth.txt is time-sorted: nothing later is in-window
        if t >= t0:
            yield line.rstrip("\n")


def redteam_in_window(
    redteam: set[RedteamKey], t0: int, t1: int
) -> set[RedteamKey]:
    return {k for k in redteam if t0 <= int(k[0]) < t1}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_lanl_slice.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/data/__init__.py apps/api/prahari/data/lanl_slice.py apps/api/tests/test_lanl_slice.py
git commit -m "feat(data): streaming LANL window slicer"
```

---

### Task 3: CICIDS real-format adapters

**Files:**
- Modify: `apps/api/prahari/parsers/cicids.py`
- Create: `apps/api/tests/fixtures/cicids_ml_sample.csv`
- Create: `apps/api/tests/test_cicids_ml.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces:
  - `parse_cicids_ml_row(row: dict) -> CanonicalEvent` and `parse_cicids_ml_file(path) -> Iterator[CanonicalEvent]` for the MachineLearningCVE variant: no IP/Timestamp; `bytes` from `Total Length of Fwd Packets`, `duration` from `Flow Duration`, label from trailing `Label`. Timestamp defaults to UNIX epoch (`1970-01-01T00:00:00Z`) since the variant carries none.
  - Existing `parse_cicids_row` hardened: guard missing `Timestamp` (default epoch) so it no longer KeyErrors on IP/timestamp-less rows.

- [ ] **Step 1: Create the fixture (real MachineLearningCVE shape, leading spaces)**

`apps/api/tests/fixtures/cicids_ml_sample.csv`:
```
 Flow Duration, Total Length of Fwd Packets, Label
38308,6,BENIGN
900000,54000,DDoS
```

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_cicids_ml.py`:
```python
from pathlib import Path

from prahari.parsers.cicids import parse_cicids_ml_file, parse_cicids_row

FIX = Path(__file__).parent / "fixtures"


def test_parse_cicids_ml_variant():
    events = list(parse_cicids_ml_file(FIX / "cicids_ml_sample.csv"))
    assert len(events) == 2
    assert all(e.event_type == "network_flow" and e.source == "cicids" for e in events)
    assert events[0].labels == []
    assert events[0].bytes == 6
    assert events[0].duration == 38308.0
    assert events[1].labels == ["attack", "DDoS"]
    assert events[1].bytes == 54000


def test_parse_cicids_row_guards_missing_timestamp():
    # MachineLearningCVE rows have no Timestamp/IP columns
    row = {"Flow Duration": 900000, "Total Length of Fwd Packets": 54000, "Label": "DDoS"}
    ev = parse_cicids_row(row)
    assert ev.bytes == 54000
    assert ev.src_ip is None
    assert ev.timestamp.year == 1970
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_cicids_ml.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_cicids_ml_file'`

- [ ] **Step 4: Implement the adapters**

Replace the body of `apps/api/prahari/parsers/cicids.py` with:
```python
from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from prahari.schema import CanonicalEvent

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


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


def _labels(label: str) -> list[str]:
    label = str(label).strip()
    return [] if label.upper() == "BENIGN" else ["attack", label]


def _timestamp(row: dict) -> datetime:
    if "Timestamp" in row and row.get("Timestamp") is not None:
        ts = pd.to_datetime(row["Timestamp"]).to_pydatetime()
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return _EPOCH


def parse_cicids_row(row: dict) -> CanonicalEvent:
    return CanonicalEvent(
        timestamp=_timestamp(row),
        event_type="network_flow",
        src_ip=(str(row["Source IP"]) if row.get("Source IP") is not None else None),
        dst_ip=(str(row["Destination IP"]) if row.get("Destination IP") is not None else None),
        action="connect",
        bytes=_to_int(row.get("Total Length of Fwd Packets")),
        duration=_to_float(row.get("Flow Duration")),
        source="cicids",
        labels=_labels(row.get("Label", "BENIGN")),
        raw=",".join(str(v) for v in row.values()),
    )


def parse_cicids_file(path: str | Path) -> Iterator[CanonicalEvent]:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    for record in df.to_dict(orient="records"):
        yield parse_cicids_row(record)


# MachineLearningCVE variant: flow features + Label only (no IP/Timestamp).
def parse_cicids_ml_row(row: dict) -> CanonicalEvent:
    return CanonicalEvent(
        timestamp=_EPOCH,
        event_type="network_flow",
        action="connect",
        bytes=_to_int(row.get("Total Length of Fwd Packets")),
        duration=_to_float(row.get("Flow Duration")),
        source="cicids",
        labels=_labels(row.get("Label", "BENIGN")),
        raw=",".join(str(v) for v in row.values()),
    )


def parse_cicids_ml_file(path: str | Path) -> Iterator[CanonicalEvent]:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    for record in df.to_dict(orient="records"):
        yield parse_cicids_ml_row(record)
```

- [ ] **Step 5: Run to verify it passes (plus regression on the original parser)**

Run: `cd apps/api && uv run pytest tests/test_cicids_ml.py tests/test_cicids.py -v`
Expected: PASS — new + original CICIDS tests green.

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/parsers/cicids.py apps/api/tests/test_cicids_ml.py apps/api/tests/fixtures/cicids_ml_sample.csv
git commit -m "feat(parsers): CICIDS MachineLearningCVE adapter + timestamp guard"
```

---

### Task 4: OTRF Sysmon real-format adapter

**Files:**
- Modify: `apps/api/prahari/parsers/process.py`
- Create: `apps/api/tests/fixtures/otrf_sample.jsonl`
- Create: `apps/api/tests/test_otrf.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces:
  - `parse_otrf_obj(obj: dict, labels: list[str] | None = None) -> CanonicalEvent | None` — returns `None` unless `EventID == 1` (process create). Maps `Hostname`→`src_host`, `User`→`source_entity`, `CommandLine`→`dest_entity`, timestamp from `@timestamp` (falls back to `UtcTime` parsed as UTC). `labels` (dataset-level ATT&CK context) attached to every emitted event.
  - `parse_otrf_lines(lines: Iterable[str], labels: list[str] | None = None) -> Iterator[CanonicalEvent]` — parses JSON-lines, skips non-EventID-1.

- [ ] **Step 1: Create the fixture (real OTRF field names)**

`apps/api/tests/fixtures/otrf_sample.jsonl`:
```
{"EventID": 1, "@timestamp": "2021-06-11T09:07:15.635Z", "UtcTime": "2021-06-12 01:07:15.633", "Hostname": "WORKSTATION5", "User": "WORKSTATION5\\APT-Simulator", "Image": "C:\\Windows\\System32\\PING.EXE", "CommandLine": "ping -n 3 127.0.0.1"}
{"EventID": 3, "@timestamp": "2021-06-11T09:07:16.000Z", "Hostname": "WORKSTATION5", "DestinationIp": "10.0.0.5"}
{"EventID": 1, "@timestamp": "2021-06-11T09:08:00.000Z", "Hostname": "WORKSTATION5", "User": "WORKSTATION5\\APT-Simulator", "Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami"}
```

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_otrf.py`:
```python
from pathlib import Path

from prahari.parsers.process import parse_otrf_lines

FIX = Path(__file__).parent / "fixtures"


def test_otrf_filters_to_process_create_and_maps_fields():
    lines = (FIX / "otrf_sample.jsonl").read_text().splitlines()
    events = list(parse_otrf_lines(lines, labels=["attack", "T1059"]))

    # only the two EventID==1 records survive (the EventID 3 network event is dropped)
    assert len(events) == 2
    e = events[0]
    assert e.event_type == "process"
    assert e.src_host == "WORKSTATION5"
    assert e.source_entity == "WORKSTATION5\\APT-Simulator"
    assert "ping" in e.dest_entity
    assert e.labels == ["attack", "T1059"]
    assert e.timestamp.year == 2021
    assert "whoami" in events[1].dest_entity
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_otrf.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_otrf_lines'`

- [ ] **Step 4: Implement the adapter**

Add to `apps/api/prahari/parsers/process.py` (keep the existing `parse_sysmon_*` functions; append these):
```python
from collections.abc import Iterable
from datetime import timezone


def _otrf_timestamp(obj: dict) -> datetime:
    ts_raw = obj.get("@timestamp")
    if ts_raw:
        return datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    utc = obj["UtcTime"]  # "2021-06-12 01:07:15.633" (naive) -> treat as UTC
    return datetime.fromisoformat(utc).replace(tzinfo=timezone.utc)


def parse_otrf_obj(obj: dict, labels: list[str] | None = None) -> CanonicalEvent | None:
    if str(obj.get("EventID")) != "1":
        return None
    return CanonicalEvent(
        timestamp=_otrf_timestamp(obj),
        event_type="process",
        source_entity=obj.get("User"),
        dest_entity=obj.get("CommandLine") or obj.get("Image"),
        src_host=obj.get("Hostname"),
        action="execute",
        outcome="success",
        source="otrf",
        labels=list(labels or []),
        raw=json.dumps(obj, sort_keys=True),
    )


def parse_otrf_lines(
    lines: Iterable[str], labels: list[str] | None = None
) -> Iterator[CanonicalEvent]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        ev = parse_otrf_obj(json.loads(line), labels=labels)
        if ev is not None:
            yield ev
```

- [ ] **Step 5: Run to verify it passes (plus regression on synthetic sysmon)**

Run: `cd apps/api && uv run pytest tests/test_otrf.py tests/test_process.py -v`
Expected: PASS — OTRF + original sysmon tests green.

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/parsers/process.py apps/api/tests/test_otrf.py apps/api/tests/fixtures/otrf_sample.jsonl
git commit -m "feat(parsers): OTRF Sysmon real-format adapter (EventID 1 + field map)"
```

---

### Task 5: Real LANL benchmark runner

**Files:**
- Create: `apps/api/prahari/data/benchmark.py`
- Create: `apps/api/tests/fixtures/lanl_bench_auth.txt`
- Create: `apps/api/tests/fixtures/lanl_bench_redteam.txt`
- Create: `apps/api/tests/test_benchmark.py`

**Interfaces:**
- Consumes: `parse_lanl_line`, `load_redteam`, `enrich`, `Sentinel`, `SignatureBaseline`, `evaluate`, `Metrics`.
- Produces:
  - `run_lanl_benchmark(auth_lines: list[str], redteam: set[tuple[str,str,str,str]], train_frac: float = 0.5, quantile: float = 0.99) -> dict[str, Metrics]` — parses+enriches auth lines (labelling red-team via the set), splits chronologically into train (benign-dominated history) and test, fits Sentinel on train, thresholds at `quantile`, scores test in batch; runs SignatureBaseline on test; returns `{"sentinel": Metrics, "signature": Metrics}`.
  - Deterministic and fast on a fixture; the real run wraps a gzip stream + `slice_auth_lines` (documented in the module docstring, not unit-tested against 7.2G).

- [ ] **Step 1: Create fixtures (a compressed lateral-movement story in LANL format)**

`apps/api/tests/fixtures/lanl_bench_auth.txt` — one user's benign history then a red-team burst. Times ascending; the red-team lines use NTLM to a never-before-seen host:
```
1000,U7@DOM1,U7@DOM1,C7,C10,Kerberos,Network,LogOn,Success
1001,U7@DOM1,U7@DOM1,C7,C10,Kerberos,Network,LogOn,Success
1002,U7@DOM1,U7@DOM1,C7,C11,Kerberos,Network,LogOn,Success
1003,U7@DOM1,U7@DOM1,C7,C10,Kerberos,Network,LogOn,Success
1004,U7@DOM1,U7@DOM1,C7,C11,Kerberos,Network,LogOn,Success
1005,U7@DOM1,U7@DOM1,C7,C10,Kerberos,Network,LogOn,Success
1006,U7@DOM1,U7@DOM1,C7,C11,Kerberos,Network,LogOn,Success
1007,U7@DOM1,U7@DOM1,C7,C10,Kerberos,Network,LogOn,Success
2000,U7@DOM1,U7@DOM1,C7,C500,NTLM,Network,LogOn,Success
2001,U7@DOM1,U7@DOM1,C7,C501,NTLM,Network,LogOn,Success
```

`apps/api/tests/fixtures/lanl_bench_redteam.txt`:
```
2000,U7@DOM1,C7,C500
2001,U7@DOM1,C7,C501
```

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_benchmark.py`:
```python
from pathlib import Path

from prahari.data.benchmark import run_lanl_benchmark
from prahari.parsers.lanl import load_redteam

FIX = Path(__file__).parent / "fixtures"


def test_real_lanl_benchmark_sentinel_beats_signature():
    auth_lines = (FIX / "lanl_bench_auth.txt").read_text().splitlines()
    redteam = load_redteam(FIX / "lanl_bench_redteam.txt")

    results = run_lanl_benchmark(auth_lines, redteam, train_frac=0.8, quantile=0.99)

    assert results["signature"].recall == 0.0        # blind to valid-cred lateral movement
    assert results["sentinel"].recall >= 0.5         # catches the NTLM-to-new-host burst
    assert results["sentinel"].recall > results["signature"].recall
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_benchmark.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.data.benchmark'`

- [ ] **Step 4: Implement the benchmark runner**

`apps/api/prahari/data/benchmark.py`:
```python
"""Real LANL benchmark: behavioural Sentinel vs signature baseline.

Fixture-driven unit test uses a tiny in-format sample. For the real run:

    import gzip
    from prahari.parsers.lanl import load_redteam
    from prahari.data.lanl_slice import slice_auth_lines, redteam_in_window
    with gzip.open("data/auth.txt.gz", "rt") as fh:
        lines = list(slice_auth_lines(fh, 750000, 780000))
    rt = redteam_in_window(load_redteam(gzip.open("data/redteam.txt.gz", "rt")), 750000, 780000)
    print(run_lanl_benchmark(lines, rt))
"""
from __future__ import annotations

from prahari.detect.metrics import Metrics, evaluate
from prahari.detect.sentinel import Sentinel
from prahari.detect.signature import SignatureBaseline
from prahari.enrich import enrich
from prahari.parsers.lanl import parse_lanl_line


def run_lanl_benchmark(
    auth_lines: list[str],
    redteam: set[tuple[str, str, str, str]],
    train_frac: float = 0.5,
    quantile: float = 0.99,
) -> dict[str, Metrics]:
    events = [enrich(parse_lanl_line(ln, redteam)) for ln in auth_lines if ln.strip()]
    events.sort(key=lambda e: e.timestamp)

    split = int(len(events) * train_frac)
    train, test = events[:split], events[split:]

    sentinel = Sentinel(random_state=0).fit(train)
    threshold = sentinel.suggest_threshold(train, quantile=quantile)
    sentinel_flags = list(sentinel.anomaly_scores(test) >= threshold)

    signature = SignatureBaseline()
    signature_flags = signature.flag_all(test)

    return {
        "sentinel": evaluate(test, sentinel_flags, positive_label="redteam"),
        "signature": evaluate(test, signature_flags, positive_label="redteam"),
    }
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_benchmark.py -v`
Expected: PASS

- [ ] **Step 6: Run the full suite (Phase 1.5 exit gate)**

Run: `cd apps/api && uv run pytest -q`
Expected: PASS — all Phase 1 + 2 + 1.5 tests green.

- [ ] **Step 7: Commit**

```bash
git add apps/api/prahari/data/benchmark.py apps/api/tests/test_benchmark.py apps/api/tests/fixtures/lanl_bench_auth.txt apps/api/tests/fixtures/lanl_bench_redteam.txt
git commit -m "feat(data): real LANL benchmark runner + Phase 1.5 exit gate"
```

---

### Task 6: Run the real benchmark and record numbers

**Files:**
- Create: `apps/api/scripts/run_real_benchmark.py`
- Create: `docs/benchmarks/lanl-real-results.md`

**Interfaces:**
- Consumes: `run_lanl_benchmark`, `slice_auth_lines`, `redteam_in_window`, `load_redteam`.
- Produces: a CLI that slices the real `data/auth.txt.gz` window, runs the benchmark, and prints real precision/recall/FPR; results recorded in a docs file for the deck.

- [ ] **Step 1: Write the runner script**

`apps/api/scripts/run_real_benchmark.py`:
```python
"""Run the LANL benchmark on the real sliced window. Manual (multi-GB): not in CI.

Usage: cd apps/api && uv run python scripts/run_real_benchmark.py [T0] [T1]
"""
from __future__ import annotations

import gzip
import sys
from pathlib import Path

from prahari.data.benchmark import run_lanl_benchmark
from prahari.data.lanl_slice import redteam_in_window, slice_auth_lines
from prahari.parsers.lanl import load_redteam

ROOT = Path(__file__).resolve().parents[3]


def main() -> None:
    t0 = int(sys.argv[1]) if len(sys.argv) > 1 else 750000
    t1 = int(sys.argv[2]) if len(sys.argv) > 2 else 780000
    with gzip.open(ROOT / "data/auth.txt.gz", "rt") as fh:
        lines = list(slice_auth_lines(fh, t0, t1))
    with gzip.open(ROOT / "data/redteam.txt.gz", "rt") as fh:
        redteam = redteam_in_window(load_redteam_lines(fh), t0, t1)
    print(f"window [{t0},{t1}): {len(lines)} auth events, {len(redteam)} red-team")
    results = run_lanl_benchmark(lines, redteam, train_frac=0.5, quantile=0.99)
    for name, m in results.items():
        print(f"{name:10s} recall={m.recall:.3f} precision={m.precision:.3f} "
              f"f1={m.f1:.3f} fpr={m.fpr:.4f} (tp={m.tp} fp={m.fp} fn={m.fn} tn={m.tn})")


def load_redteam_lines(fh) -> set[tuple[str, str, str, str]]:
    keys = set()
    for line in fh:
        line = line.strip()
        if line:
            t, u, s, d = line.split(",")
            keys.add((t, u, s, d))
    return keys


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run it on the real data**

Run: `cd apps/api && uv run python scripts/run_real_benchmark.py 750000 780000`
Expected: prints the window size and two metric lines. **Record the actual numbers** (do not fabricate — paste whatever prints).

- [ ] **Step 3: Record results for the deck**

Create `docs/benchmarks/lanl-real-results.md` with a short table containing the **actual** printed numbers, the window used, event/red-team counts, and one line on interpretation (behavioural recall vs signature 0). If the real numbers are weak (e.g. Sentinel recall < 0.4), note it honestly and add a follow-up item to tune `quantile`/features rather than overclaiming.

- [ ] **Step 4: Commit**

```bash
git add apps/api/scripts/run_real_benchmark.py docs/benchmarks/lanl-real-results.md
git commit -m "feat(data): real-benchmark CLI + recorded LANL results"
```

---

## Self-Review

**Spec coverage (Phase 1.5 scope):**
- Batch scoring for scale → Task 1 ✅
- LANL 7.2G handling via streaming window slice → Task 2 ✅
- CICIDS both variants (spec §11, two-variant reality) → Task 3 ✅
- OTRF real field mapping + EventID filter → Task 4 ✅
- Real benchmark = real precision/recall/FPR on LANL red-team (spec §10, eval focus) → Tasks 5, 6 ✅
- Deferred (correct): LANL proc.txt parser (only if endpoint track needs it later), GeneratedLabelledFlows full-timeline wiring (Phase 3 correlation), Phase 3 agents.

**Placeholder scan:** No TBD/TODO. Task 6 Step 3 deliberately records *actual* runtime numbers (can't be pre-written) and instructs honesty if weak — this is a real instruction, not a placeholder.

**Type consistency:** `anomaly_scores` returns `np.ndarray` in both detectors (Task 1), consumed in Task 5 via `>= threshold`. `slice_auth_lines`/`redteam_in_window` (Task 2) reused in Task 6. `parse_cicids_ml_file`, `parse_otrf_lines` new symbols consistent between impl and tests. `run_lanl_benchmark(auth_lines, redteam, train_frac, quantile)` signature identical in Task 5 test, impl, and Task 6 script. Red-team key `(time, src_user, src_comp, dst_comp)` consistent across slicer, benchmark, and Phase 1's `load_redteam`.

**Risk note:** Task 6 is empirical — the real LANL numbers might need `quantile`/`train_frac` tuning to look strong. The plan handles this honestly (Step 3) rather than asserting a target in CI, keeping the unit test (Task 5) on a controlled fixture.
