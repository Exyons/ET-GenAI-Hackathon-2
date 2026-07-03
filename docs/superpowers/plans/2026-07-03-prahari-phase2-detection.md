# Prahari Phase 2: Sentinel Detection & Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the behavioural anomaly detector (Sentinel) with real ML on per-entity auth baselines and network flows, a deliberately-weak signature baseline for contrast, and a metrics harness — so we can put precision/recall/FPR numbers on screen and show Sentinel catching low-and-slow attacks the signature baseline misses.

**Architecture:** Deterministic per-entity feature engineering (auth novelty features) feeds a scikit-learn `IsolationForest`. Two detector tracks: auth (`Sentinel`) and network flow (`NetworkSentinel`). A `SignatureBaseline` models classic indicator matching (known-bad IPs / command substrings) that stays silent on behavioural low-and-slow attacks. A pure `evaluate()` harness computes TP/FP/FN/TN → precision/recall/F1/FPR against the ground-truth `labels` already on every `CanonicalEvent`.

**Tech Stack:** Python 3.14 + uv, scikit-learn (IsolationForest), pytest. Builds on Phase 1's `CanonicalEvent`, parsers, and `enrich`.

## Global Constraints

- Package root `apps/api`, package `prahari`; run tests with `cd apps/api && uv run pytest`.
- Pydantic v2, timezone-aware UTC datetimes, Python 3.14.
- **Real ML does detection; no LLM in this phase.** IsolationForest with fixed `random_state=0` for reproducible scores.
- Ground truth = the `labels` list on `CanonicalEvent` (`"redteam"` for LANL, `"attack"` for CICIDS). Metrics come only from labelled data.
- Anomaly score convention: **higher = more anomalous** (we negate sklearn's `score_samples`).
- Commit after every task with the message shown in its final step.

---

### Task 1: Add `auth_type` to schema + LANL parser

**Files:**
- Modify: `apps/api/prahari/schema.py` (add one field)
- Modify: `apps/api/prahari/parsers/lanl.py` (set the field)
- Modify: `apps/api/tests/test_lanl.py` (assert the field)

**Interfaces:**
- Consumes: existing `CanonicalEvent`, `parse_lanl_line`.
- Produces: `CanonicalEvent.auth_type: str | None` (default `None`); LANL events carry the raw auth mechanism string (e.g. `"NTLM"`, `"Kerberos"`). Downstream auth feature engineering reads `event.auth_type`.

- [ ] **Step 1: Extend the failing LANL test**

In `apps/api/tests/test_lanl.py`, add to the end of `test_lanl_parses_and_labels_redteam` (the flagged event `e` is `U342@DOM1`'s NTLM login):
```python
    assert e.auth_type == "NTLM"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_lanl.py -v`
Expected: FAIL — `AttributeError: 'CanonicalEvent' object has no attribute 'auth_type'`

- [ ] **Step 3: Add the field to the schema**

In `apps/api/prahari/schema.py`, add this field to `CanonicalEvent` immediately after the `outcome` field:
```python
    auth_type: str | None = None
```

- [ ] **Step 4: Set it in the LANL parser**

In `apps/api/prahari/parsers/lanl.py`, inside `parse_lanl_line`, add `auth_type=atype,` to the `CanonicalEvent(...)` construction (place it right after the `outcome=success.lower(),` line):
```python
        outcome=success.lower(),
        auth_type=atype,
```

- [ ] **Step 5: Run to verify it passes (plus regression)**

Run: `cd apps/api && uv run pytest tests/test_lanl.py tests/test_schema.py tests/test_ingest_e2e.py -v`
Expected: PASS — all tests green.

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/schema.py apps/api/prahari/parsers/lanl.py apps/api/tests/test_lanl.py
git commit -m "feat(schema): add auth_type field populated by LANL parser"
```

---

### Task 2: AuthBaseline — per-entity behavioural feature engineering

**Files:**
- Create: `apps/api/prahari/detect/__init__.py`
- Create: `apps/api/prahari/detect/features_auth.py`
- Create: `apps/api/tests/test_features_auth.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces:
  - `class AuthBaseline` with `fit(events: Iterable[CanonicalEvent]) -> AuthBaseline` (learns per-user normal behaviour from `auth` events only) and `featurize(event: CanonicalEvent) -> list[float]`.
  - `featurize` returns exactly 5 floats in this order: `[is_new_dest, is_new_src, auth_type_rarity, hour_novelty, dest_criticality]`.
  - `FEATURE_NAMES: list[str]` = the 5 names above.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_features_auth.py`:
```python
from datetime import datetime, timezone

from prahari.detect.features_auth import FEATURE_NAMES, AuthBaseline
from prahari.schema import CanonicalEvent


def _auth(user, src, dst, atype, hour, crit="unknown", labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, hour, 0, 0, tzinfo=timezone.utc),
        event_type="auth",
        source_entity=user,
        src_host=src,
        dst_host=dst,
        auth_type=atype,
        asset_criticality=crit,
        source="lanl",
        labels=labels or [],
        raw="x",
    )


def test_feature_names_length():
    assert len(FEATURE_NAMES) == 5


def test_normal_event_scores_all_low():
    train = [_auth("U100", "C1", "C2", "Kerberos", 15) for _ in range(5)]
    base = AuthBaseline().fit(train)
    f = base.featurize(_auth("U100", "C1", "C2", "Kerberos", 15))
    # seen dest, seen src, common auth type, seen hour, unknown criticality
    assert f == [0.0, 0.0, 0.0, 0.0, 0.0]


def test_novel_event_scores_high():
    train = [_auth("U342", "C1115", "C10", "Kerberos", 15) for _ in range(5)]
    base = AuthBaseline().fit(train)
    # new dest, new... src is seen (C1115), NTLM never seen, hour 3 novel, critical asset
    f = base.featurize(_auth("U342", "C1115", "C553", "NTLM", 3, crit="critical"))
    is_new_dest, is_new_src, atype_rarity, hour_novelty, dest_crit = f
    assert is_new_dest == 1.0
    assert is_new_src == 0.0
    assert atype_rarity == 1.0  # NTLM never in this user's baseline
    assert hour_novelty == 1.0
    assert dest_crit == 1.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_features_auth.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.detect'`

- [ ] **Step 3: Implement the baseline**

`apps/api/prahari/detect/__init__.py`: (empty file)

`apps/api/prahari/detect/features_auth.py`:
```python
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable

from prahari.schema import CanonicalEvent

FEATURE_NAMES = [
    "is_new_dest",
    "is_new_src",
    "auth_type_rarity",
    "hour_novelty",
    "dest_criticality",
]

_CRIT_NUM = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0, "unknown": 0.0}


class AuthBaseline:
    def __init__(self) -> None:
        self.user_dests: dict[str, set[str]] = defaultdict(set)
        self.user_srcs: dict[str, set[str]] = defaultdict(set)
        self.user_authtype: dict[str, Counter] = defaultdict(Counter)
        self.user_hours: dict[str, set[int]] = defaultdict(set)

    def fit(self, events: Iterable[CanonicalEvent]) -> "AuthBaseline":
        for e in events:
            if e.event_type != "auth":
                continue
            u = e.source_entity or "?"
            if e.dst_host:
                self.user_dests[u].add(e.dst_host)
            if e.src_host:
                self.user_srcs[u].add(e.src_host)
            if e.auth_type:
                self.user_authtype[u][e.auth_type] += 1
            self.user_hours[u].add(e.timestamp.hour)
        return self

    def featurize(self, e: CanonicalEvent) -> list[float]:
        u = e.source_entity or "?"
        is_new_dest = 0.0 if e.dst_host in self.user_dests.get(u, set()) else 1.0
        is_new_src = 0.0 if e.src_host in self.user_srcs.get(u, set()) else 1.0
        counts = self.user_authtype.get(u, Counter())
        total = sum(counts.values())
        atype_rarity = 1.0 - (counts.get(e.auth_type, 0) / total) if total else 1.0
        hour_novelty = 0.0 if e.timestamp.hour in self.user_hours.get(u, set()) else 1.0
        dest_crit = _CRIT_NUM.get(e.asset_criticality, 0.0)
        return [is_new_dest, is_new_src, atype_rarity, hour_novelty, dest_crit]
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_features_auth.py -v`
Expected: PASS (all three tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/detect/__init__.py apps/api/prahari/detect/features_auth.py apps/api/tests/test_features_auth.py
git commit -m "feat(detect): per-entity auth behavioural feature engineering"
```

---

### Task 3: Sentinel — IsolationForest auth anomaly detector

**Files:**
- Modify: `apps/api/pyproject.toml` (add scikit-learn)
- Create: `apps/api/prahari/detect/sentinel.py`
- Create: `apps/api/tests/test_sentinel.py`

**Interfaces:**
- Consumes: `AuthBaseline`, `CanonicalEvent`.
- Produces:
  - `class Sentinel` with:
    - `__init__(self, random_state: int = 0)`
    - `fit(train_events: list[CanonicalEvent]) -> Sentinel` (fits baseline + IsolationForest on featurized auth events)
    - `anomaly_score(event: CanonicalEvent) -> float` (higher = more anomalous)
    - `suggest_threshold(train_events: list[CanonicalEvent], quantile: float = 0.95) -> float`
    - `flag_anomalies(events: list[CanonicalEvent], threshold: float) -> list[bool]`

- [ ] **Step 1: Add scikit-learn dependency**

In `apps/api/pyproject.toml`, add `"scikit-learn>=1.5"` to the `dependencies` list (after `"pandas>=2.2",`).

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_sentinel.py`:
```python
from datetime import datetime, timezone

from prahari.detect.sentinel import Sentinel
from prahari.schema import CanonicalEvent


def _auth(user, src, dst, atype, hour, crit="unknown", labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, hour, 0, 0, tzinfo=timezone.utc),
        event_type="auth",
        source_entity=user,
        src_host=src,
        dst_host=dst,
        auth_type=atype,
        asset_criticality=crit,
        source="lanl",
        labels=labels or [],
        raw="x",
    )


def _normal_traffic(n=30):
    # homogeneous benign behaviour for one user
    return [_auth("U100", "C1", "C2", "Kerberos", 15) for _ in range(n)]


def test_redteam_event_is_most_anomalous():
    train = _normal_traffic()
    sentinel = Sentinel(random_state=0).fit(train)

    redteam = _auth("U100", "C1", "C553", "NTLM", 3, crit="critical", labels=["redteam"])
    population = train + [redteam]
    scores = [sentinel.anomaly_score(e) for e in population]

    # the red-team event has the single highest anomaly score
    assert scores.index(max(scores)) == len(population) - 1


def test_flag_anomalies_catches_redteam_above_threshold():
    train = _normal_traffic()
    sentinel = Sentinel(random_state=0).fit(train)
    threshold = sentinel.suggest_threshold(train, quantile=0.95)

    redteam = _auth("U100", "C1", "C553", "NTLM", 3, crit="critical", labels=["redteam"])
    flags = sentinel.flag_anomalies(train + [redteam], threshold)

    assert flags[-1] is True  # red-team flagged
    assert sum(flags[:-1]) <= 2  # almost no false positives on benign
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_sentinel.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.detect.sentinel'`

- [ ] **Step 4: Implement Sentinel**

`apps/api/prahari/detect/sentinel.py`:
```python
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from prahari.detect.features_auth import AuthBaseline
from prahari.schema import CanonicalEvent


class Sentinel:
    def __init__(self, random_state: int = 0) -> None:
        self.random_state = random_state
        self.baseline = AuthBaseline()
        self.model = IsolationForest(random_state=random_state, contamination="auto")

    def _auth_only(self, events: list[CanonicalEvent]) -> list[CanonicalEvent]:
        return [e for e in events if e.event_type == "auth"]

    def fit(self, train_events: list[CanonicalEvent]) -> "Sentinel":
        auth = self._auth_only(train_events)
        self.baseline.fit(auth)
        x = np.array([self.baseline.featurize(e) for e in auth], dtype=float)
        self.model.fit(x)
        return self

    def anomaly_score(self, event: CanonicalEvent) -> float:
        x = np.array([self.baseline.featurize(event)], dtype=float)
        # score_samples: lower = more abnormal; negate so higher = more anomalous
        return float(-self.model.score_samples(x)[0])

    def suggest_threshold(
        self, train_events: list[CanonicalEvent], quantile: float = 0.95
    ) -> float:
        auth = self._auth_only(train_events)
        scores = np.array([self.anomaly_score(e) for e in auth], dtype=float)
        return float(np.quantile(scores, quantile))

    def flag_anomalies(
        self, events: list[CanonicalEvent], threshold: float
    ) -> list[bool]:
        return [self.anomaly_score(e) >= threshold for e in events]
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_sentinel.py -v`
Expected: PASS (both tests)

- [ ] **Step 6: Commit**

```bash
git add apps/api/pyproject.toml apps/api/prahari/detect/sentinel.py apps/api/tests/test_sentinel.py
git commit -m "feat(detect): Sentinel IsolationForest auth anomaly detector"
```

---

### Task 4: NetworkSentinel — IsolationForest on flow features

**Files:**
- Create: `apps/api/prahari/detect/network.py`
- Create: `apps/api/tests/test_network.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces:
  - `class NetworkSentinel` with `__init__(self, random_state: int = 0)`, `fit(train_events: list[CanonicalEvent]) -> NetworkSentinel` (fits on `network_flow` events' `[bytes, duration]`), and `anomaly_score(event: CanonicalEvent) -> float` (higher = more anomalous). Missing `bytes`/`duration` are treated as `0.0`.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_network.py`:
```python
from datetime import datetime, timezone

from prahari.detect.network import NetworkSentinel
from prahari.schema import CanonicalEvent


def _flow(nbytes, duration, labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, tzinfo=timezone.utc),
        event_type="network_flow",
        bytes=nbytes,
        duration=duration,
        source="cicids",
        labels=labels or [],
        raw="x",
    )


def test_attack_flow_is_most_anomalous():
    train = [_flow(200 + i, 1000 + i) for i in range(30)]  # tight benign cluster
    net = NetworkSentinel(random_state=0).fit(train)

    attack = _flow(54000, 900000, labels=["attack", "DDoS"])
    population = train + [attack]
    scores = [net.anomaly_score(e) for e in population]

    assert scores.index(max(scores)) == len(population) - 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_network.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.detect.network'`

- [ ] **Step 3: Implement NetworkSentinel**

`apps/api/prahari/detect/network.py`:
```python
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from prahari.schema import CanonicalEvent


def _features(e: CanonicalEvent) -> list[float]:
    return [float(e.bytes or 0), float(e.duration or 0.0)]


class NetworkSentinel:
    def __init__(self, random_state: int = 0) -> None:
        self.model = IsolationForest(random_state=random_state, contamination="auto")

    def fit(self, train_events: list[CanonicalEvent]) -> "NetworkSentinel":
        flows = [e for e in train_events if e.event_type == "network_flow"]
        x = np.array([_features(e) for e in flows], dtype=float)
        self.model.fit(x)
        return self

    def anomaly_score(self, event: CanonicalEvent) -> float:
        x = np.array([_features(event)], dtype=float)
        return float(-self.model.score_samples(x)[0])
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_network.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/detect/network.py apps/api/tests/test_network.py
git commit -m "feat(detect): NetworkSentinel IsolationForest flow detector"
```

---

### Task 5: SignatureBaseline — the detector built to lose

**Files:**
- Create: `apps/api/prahari/detect/signature.py`
- Create: `apps/api/tests/test_signature.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces:
  - `class SignatureBaseline` with `__init__(self, bad_ips: set[str] | None = None, bad_cmd_substrings: set[str] | None = None)`, `flag(event: CanonicalEvent) -> bool` (True only if `dst_ip`/`src_ip` in `bad_ips`, or a `process` event's `dest_entity` contains a bad substring), and `flag_all(events: list[CanonicalEvent]) -> list[bool]`.
  - Models classic signature/IOC matching: it has **no** concept of behavioural novelty, so low-and-slow auth attacks pass straight through.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_signature.py`:
```python
from datetime import datetime, timezone

from prahari.detect.signature import SignatureBaseline
from prahari.schema import CanonicalEvent


def _auth(dst, labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 3, 0, tzinfo=timezone.utc),
        event_type="auth",
        source_entity="U342",
        src_host="C1115",
        dst_host=dst,
        auth_type="NTLM",
        source="lanl",
        labels=labels or [],
        raw="x",
    )


def _flow(dst_ip, labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, tzinfo=timezone.utc),
        event_type="network_flow",
        dst_ip=dst_ip,
        source="cicids",
        labels=labels or [],
        raw="x",
    )


def test_signature_silent_on_lowandslow_auth():
    sig = SignatureBaseline(bad_ips={"203.0.113.9"})
    # the red-team lateral movement is an auth event with no known bad indicator
    assert sig.flag(_auth("C553", labels=["redteam"])) is False


def test_signature_catches_known_bad_ip():
    sig = SignatureBaseline(bad_ips={"203.0.113.9"})
    assert sig.flag(_flow("203.0.113.9", labels=["attack"])) is True
    assert sig.flag(_flow("52.84.23.17")) is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_signature.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.detect.signature'`

- [ ] **Step 3: Implement SignatureBaseline**

`apps/api/prahari/detect/signature.py`:
```python
from __future__ import annotations

from prahari.schema import CanonicalEvent


class SignatureBaseline:
    def __init__(
        self,
        bad_ips: set[str] | None = None,
        bad_cmd_substrings: set[str] | None = None,
    ) -> None:
        self.bad_ips = bad_ips or set()
        self.bad_cmd_substrings = bad_cmd_substrings or set()

    def flag(self, event: CanonicalEvent) -> bool:
        if event.dst_ip in self.bad_ips or event.src_ip in self.bad_ips:
            return True
        if event.event_type == "process" and event.dest_entity:
            cmd = event.dest_entity.lower()
            if any(sub.lower() in cmd for sub in self.bad_cmd_substrings):
                return True
        return False

    def flag_all(self, events: list[CanonicalEvent]) -> list[bool]:
        return [self.flag(e) for e in events]
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_signature.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/detect/signature.py apps/api/tests/test_signature.py
git commit -m "feat(detect): signature baseline (indicator matching, no behaviour)"
```

---

### Task 6: Metrics harness

**Files:**
- Create: `apps/api/prahari/detect/metrics.py`
- Create: `apps/api/tests/test_metrics.py`

**Interfaces:**
- Consumes: `CanonicalEvent`.
- Produces:
  - `@dataclass Metrics` with int fields `tp, fp, fn, tn` and float properties `precision`, `recall`, `f1`, `fpr` (each returns `0.0` when its denominator is 0).
  - `evaluate(events: list[CanonicalEvent], predicted: list[bool], positive_label: str = "redteam") -> Metrics` — ground-truth positive iff `positive_label in event.labels`; `predicted[i]` aligns with `events[i]`.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_metrics.py`:
```python
from datetime import datetime, timezone

from prahari.detect.metrics import Metrics, evaluate
from prahari.schema import CanonicalEvent


def _ev(labels):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, tzinfo=timezone.utc),
        event_type="auth",
        source="lanl",
        labels=labels,
        raw="x",
    )


def test_metrics_math():
    # 2 positives (redteam), 2 negatives
    events = [_ev(["redteam"]), _ev(["redteam"]), _ev([]), _ev([])]
    predicted = [True, False, True, False]  # tp=1, fn=1, fp=1, tn=1
    m = evaluate(events, predicted)
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 1, 1, 1)
    assert m.precision == 0.5
    assert m.recall == 0.5
    assert m.fpr == 0.5
    assert abs(m.f1 - 0.5) < 1e-9


def test_metrics_zero_denominators():
    m = Metrics(tp=0, fp=0, fn=0, tn=5)
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1 == 0.0
    assert m.fpr == 0.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_metrics.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.detect.metrics'`

- [ ] **Step 3: Implement the harness**

`apps/api/prahari/detect/metrics.py`:
```python
from __future__ import annotations

from dataclasses import dataclass

from prahari.schema import CanonicalEvent


@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0


def evaluate(
    events: list[CanonicalEvent],
    predicted: list[bool],
    positive_label: str = "redteam",
) -> Metrics:
    tp = fp = fn = tn = 0
    for event, flag in zip(events, predicted, strict=True):
        is_positive = positive_label in event.labels
        if flag and is_positive:
            tp += 1
        elif flag and not is_positive:
            fp += 1
        elif not flag and is_positive:
            fn += 1
        else:
            tn += 1
    return Metrics(tp=tp, fp=fp, fn=fn, tn=tn)
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_metrics.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/detect/metrics.py apps/api/tests/test_metrics.py
git commit -m "feat(detect): precision/recall/F1/FPR metrics harness"
```

---

### Task 7: Detection comparison — the money metric (Phase 2 exit gate)

**Files:**
- Create: `apps/api/prahari/detect/compare.py`
- Create: `apps/api/tests/test_compare.py`

**Interfaces:**
- Consumes: `Sentinel`, `SignatureBaseline`, `evaluate`, `Metrics`, `CanonicalEvent`.
- Produces:
  - `compare_detectors(train: list[CanonicalEvent], test: list[CanonicalEvent], bad_ips: set[str] | None = None, quantile: float = 0.95) -> dict[str, Metrics]` — fits Sentinel on `train`, thresholds at `quantile`, flags `test`; runs `SignatureBaseline` on `test`; returns `{"sentinel": Metrics, "signature": Metrics}` both scored against `"redteam"` labels.
  - This is the demo's headline: behavioural recall ≫ signature recall on low-and-slow auth.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_compare.py`:
```python
from datetime import datetime, timezone

from prahari.detect.compare import compare_detectors
from prahari.schema import CanonicalEvent


def _auth(user, src, dst, atype, hour, crit="unknown", labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, hour, 0, 0, tzinfo=timezone.utc),
        event_type="auth",
        source_entity=user,
        src_host=src,
        dst_host=dst,
        auth_type=atype,
        asset_criticality=crit,
        source="lanl",
        labels=labels or [],
        raw="x",
    )


def test_sentinel_beats_signature_on_lowandslow():
    train = [_auth("U100", "C1", "C2", "Kerberos", 15) for _ in range(30)]
    # test set = benign traffic + 2 red-team lateral-movement auths
    test = [_auth("U100", "C1", "C2", "Kerberos", 15) for _ in range(20)]
    test.append(_auth("U100", "C1", "C553", "NTLM", 3, crit="critical", labels=["redteam"]))
    test.append(_auth("U100", "C1", "C777", "NTLM", 2, crit="high", labels=["redteam"]))

    results = compare_detectors(train, test, bad_ips={"203.0.113.9"}, quantile=0.95)

    # signature is blind to behavioural low-and-slow auth
    assert results["signature"].recall == 0.0
    # Sentinel catches the red-team lateral movement
    assert results["sentinel"].recall >= 0.5
    assert results["sentinel"].recall > results["signature"].recall
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_compare.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.detect.compare'`

- [ ] **Step 3: Implement the comparison**

`apps/api/prahari/detect/compare.py`:
```python
from __future__ import annotations

from prahari.detect.metrics import Metrics, evaluate
from prahari.detect.sentinel import Sentinel
from prahari.detect.signature import SignatureBaseline
from prahari.schema import CanonicalEvent


def compare_detectors(
    train: list[CanonicalEvent],
    test: list[CanonicalEvent],
    bad_ips: set[str] | None = None,
    quantile: float = 0.95,
) -> dict[str, Metrics]:
    sentinel = Sentinel(random_state=0).fit(train)
    threshold = sentinel.suggest_threshold(train, quantile=quantile)
    sentinel_flags = sentinel.flag_anomalies(test, threshold)

    signature = SignatureBaseline(bad_ips=bad_ips)
    signature_flags = signature.flag_all(test)

    return {
        "sentinel": evaluate(test, sentinel_flags, positive_label="redteam"),
        "signature": evaluate(test, signature_flags, positive_label="redteam"),
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_compare.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite (Phase 2 exit gate)**

Run: `cd apps/api && uv run pytest -q`
Expected: PASS — all Phase 1 + Phase 2 tests green.

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/detect/compare.py apps/api/tests/test_compare.py
git commit -m "feat(detect): Sentinel-vs-signature comparison + Phase 2 exit gate"
```

---

## Self-Review

**Spec coverage (Phase 2 scope):**
- Sentinel two-track behavioural ML (spec §5) → Tasks 2, 3 (auth), 4 (network) ✅
- Interpretable auth novelty features / pass-the-hash signal (spec §5) → Task 2 (`auth_type_rarity` captures NTLM-where-Kerberos-normal), Task 1 (auth_type) ✅
- Signature baseline built to lose (spec §5) → Task 5 ✅
- Metrics: precision/recall/F1/FPR, clean provenance (spec §10) → Task 6 ✅
- Headline contrast: Sentinel recall > signature recall on low-and-slow (spec §5, §7 differentiator #2) → Task 7 ✅
- Deferred to later plans (correct): Correlator/kill-chain (Phase 3), Attributor RAG, Predictor, dashboard, response, OTRF attribution-accuracy harness.

**Placeholder scan:** No TBD/TODO. Every code step shows complete code. No "add error handling"-style vagueness.

**Type consistency:** `CanonicalEvent.auth_type` added in Task 1, read in Task 2 (`featurize`). `AuthBaseline.fit/featurize` (Task 2) used by `Sentinel` (Task 3). `Sentinel.fit/anomaly_score/suggest_threshold/flag_anomalies` (Task 3) used by `compare_detectors` (Task 7). `SignatureBaseline.flag/flag_all` (Task 5) used in Task 7. `Metrics`/`evaluate` (Task 6) used in Task 7. `anomaly_score` convention (higher = anomalous) consistent across Sentinel + NetworkSentinel. All 5 auth features named consistently via `FEATURE_NAMES`.

**Test-robustness note:** IsolationForest tests assert *ranking* ("red-team is the single most anomalous") and thresholded recall, not exact scores — robust to sklearn version drift given `random_state=0` and deliberately well-separated synthetic fixtures. On real LANL data the same API holds; thresholds get tuned on real score distributions in Phase 4's dashboard, not hard-coded.
