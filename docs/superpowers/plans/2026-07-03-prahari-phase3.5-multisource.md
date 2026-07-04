# Prahari Phase 3.5: Real Multi-Source Fusion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire LANL `proc.txt` (process) and `flows.txt` (network) so a real red-team target host fuses auth + process + network telemetry into a genuine `high_confidence` multi-source incident — the real-data version of the C553 money moment.

**Architecture:** Two new deterministic parsers map LANL proc/flow records to `CanonicalEvent`. A host-scoped multi-source slicer streams all three time-sorted gzip files for a target host set and window. A builder enriches, merges, and correlates by target host (Phase 3 `correlate` + `target_of`), yielding real incidents; a script runs it on a real red-team host and records the fused timeline. No new ML — this proves fusion on real data.

**Tech Stack:** Python 3.14 + uv, pytest. Builds on Phase 1 parsers/`enrich`, Phase 3 `correlate`/`Incident`, Phase 1.5 `slice_auth_lines`.

## Global Constraints

- Package root `apps/api`, package `prahari`; tests: `cd apps/api && uv run pytest`.
- No raw data committed; unit tests use tiny fixtures. The real run is a manual multi-GB script.
- LANL formats (verified 2026-07-03):
  - `proc.txt`: `time,user,computer,process,{Start|End}` — only `Start` = process creation.
  - `flows.txt`: `time,duration,src_comp,src_port,dst_comp,dst_port,protocol,packets,bytes`.
- Sources are distinct so fusion counts: auth `lanl`, process `lanl_proc`, network `lanl_flow`.
- Correlation entity = **target host**: `target_of` returns `dst_host` for auth, `src_host` for process/network. Proc `src_host`=computer; flow `src_host`=src_comp. A compromised host thus gathers auth-in + proc-on + flow-from.
- Commit after every task with the message in its final step.

---

### Task 1: LANL process parser

**Files:**
- Modify: `apps/api/prahari/parsers/lanl.py`
- Create: `apps/api/tests/fixtures/lanl_proc_sample.txt`
- Create: `apps/api/tests/test_lanl_proc.py`

**Interfaces:**
- Consumes: `CanonicalEvent`, `LANL_EPOCH`.
- Produces:
  - `parse_lanl_proc_line(line: str) -> CanonicalEvent | None` — returns `None` for non-`Start` actions; else `event_type="process"`, `source_entity=user`, `src_host=computer`, `action="execute"`, `dest_entity=process`, `source="lanl_proc"`.
  - `parse_lanl_proc_file(path) -> Iterator[CanonicalEvent]`.

- [ ] **Step 1: Create fixture**

`apps/api/tests/fixtures/lanl_proc_sample.txt`:
```
150562,C1003$@DOM1,C1003,P47,Start
150568,C1003$@DOM1,C1003,P47,End
150663,U620@DOM1,C1003,P7,Start
```

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_lanl_proc.py`:
```python
from pathlib import Path

from prahari.parsers.lanl import parse_lanl_proc_file

FIX = Path(__file__).parent / "fixtures"


def test_proc_parses_start_events_only():
    events = list(parse_lanl_proc_file(FIX / "lanl_proc_sample.txt"))
    # the End record is dropped
    assert len(events) == 2
    assert all(e.event_type == "process" and e.source == "lanl_proc" for e in events)
    e = events[0]
    assert e.src_host == "C1003"
    assert e.source_entity == "C1003$@DOM1"
    assert e.action == "execute"
    assert e.dest_entity == "P47"
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_lanl_proc.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_lanl_proc_file'`

- [ ] **Step 4: Implement (append to `apps/api/prahari/parsers/lanl.py`)**

```python
def parse_lanl_proc_line(line: str) -> CanonicalEvent | None:
    t, user, computer, process, action = line.split(",")
    if action.strip() != "Start":
        return None
    return CanonicalEvent(
        timestamp=LANL_EPOCH + timedelta(seconds=int(t)),
        event_type="process",
        source_entity=user,
        src_host=computer,
        action="execute",
        dest_entity=process,
        source="lanl_proc",
        raw=line,
    )


def parse_lanl_proc_file(path: str | Path) -> Iterator[CanonicalEvent]:
    for line in Path(path).read_text().splitlines():
        if line.strip():
            ev = parse_lanl_proc_line(line)
            if ev is not None:
                yield ev
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_lanl_proc.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/parsers/lanl.py apps/api/tests/test_lanl_proc.py apps/api/tests/fixtures/lanl_proc_sample.txt
git commit -m "feat(parsers): LANL process (proc.txt) parser"
```

---

### Task 2: LANL flow parser

**Files:**
- Modify: `apps/api/prahari/parsers/lanl.py`
- Create: `apps/api/tests/fixtures/lanl_flow_sample.txt`
- Create: `apps/api/tests/test_lanl_flow.py`

**Interfaces:**
- Consumes: `CanonicalEvent`, `LANL_EPOCH`.
- Produces:
  - `parse_lanl_flow_line(line: str) -> CanonicalEvent` — `event_type="network_flow"`, `src_host=src_comp`, `dst_host=dst_comp`, `bytes=int(bytes)`, `duration=float(duration)`, `action="connect"`, `source="lanl_flow"`.
  - `parse_lanl_flow_file(path) -> Iterator[CanonicalEvent]`.

- [ ] **Step 1: Create fixture**

`apps/api/tests/fixtures/lanl_flow_sample.txt`:
```
150007,0,C17693,443,C5074,N8015,6,6,563
150017,2,C1003,N93,C5074,443,6,10,4200
```

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_lanl_flow.py`:
```python
from pathlib import Path

from prahari.parsers.lanl import parse_lanl_flow_file

FIX = Path(__file__).parent / "fixtures"


def test_flow_parses_fields():
    events = list(parse_lanl_flow_file(FIX / "lanl_flow_sample.txt"))
    assert len(events) == 2
    assert all(e.event_type == "network_flow" and e.source == "lanl_flow" for e in events)
    e = events[0]
    assert e.src_host == "C17693"
    assert e.dst_host == "C5074"
    assert e.bytes == 563
    assert e.action == "connect"
    assert events[1].bytes == 4200
    assert events[1].duration == 2.0
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_lanl_flow.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_lanl_flow_file'`

- [ ] **Step 4: Implement (append to `apps/api/prahari/parsers/lanl.py`)**

```python
def parse_lanl_flow_line(line: str) -> CanonicalEvent:
    t, dur, sc, _sp, dc, _dp, _proto, _pkts, byts = line.split(",")
    return CanonicalEvent(
        timestamp=LANL_EPOCH + timedelta(seconds=int(t)),
        event_type="network_flow",
        src_host=sc,
        dst_host=dc,
        action="connect",
        bytes=int(byts),
        duration=float(dur),
        source="lanl_flow",
        raw=line,
    )


def parse_lanl_flow_file(path: str | Path) -> Iterator[CanonicalEvent]:
    for line in Path(path).read_text().splitlines():
        if line.strip():
            yield parse_lanl_flow_line(line)
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_lanl_flow.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/parsers/lanl.py apps/api/tests/test_lanl_flow.py apps/api/tests/fixtures/lanl_flow_sample.txt
git commit -m "feat(parsers): LANL flow (flows.txt) parser"
```

---

### Task 3: Host-scoped multi-source slice filter

**Files:**
- Modify: `apps/api/prahari/data/lanl_slice.py`
- Create: `apps/api/tests/test_multisource_slice.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `lines_for_hosts(lines, hosts, t0, t1, host_fields) -> Iterator[str]` — yields lines whose time is in `[t0, t1)` and where any column index in `host_fields` is in `hosts`. Stops when `time >= t1` (files are time-sorted). `host_fields` differ per file: auth `(3, 4)` (src/dst comp), proc `(2,)` (computer), flow `(2, 4)` (src/dst comp).

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_multisource_slice.py`:
```python
from prahari.data.lanl_slice import lines_for_hosts


def test_lines_for_hosts_filters_by_column_and_window():
    proc = [
        "150001,U1@D,C999,P1,Start",
        "150562,C1003$@D,C1003,P47,Start",   # host match (col 2)
        "150900,U2@D,C1003,P7,Start",        # host match
        "160000,U3@D,C1003,P8,Start",        # out of window -> stop
    ]
    out = list(lines_for_hosts(iter(proc), hosts={"C1003"}, t0=150000, t1=160000, host_fields=(2,)))
    assert [l.split(",")[0] for l in out] == ["150562", "150900"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_multisource_slice.py -v`
Expected: FAIL — `ImportError: cannot import name 'lines_for_hosts'`

- [ ] **Step 3: Implement (append to `apps/api/prahari/data/lanl_slice.py`)**

```python
def lines_for_hosts(
    lines: Iterable[str], hosts: set[str], t0: int, t1: int, host_fields: tuple[int, ...]
) -> Iterator[str]:
    for line in lines:
        parts = line.rstrip("\n").split(",")
        if not parts or not parts[0].isdigit():
            continue
        t = int(parts[0])
        if t >= t1:
            return
        if t < t0:
            continue
        if any(len(parts) > f and parts[f] in hosts for f in host_fields):
            yield line.rstrip("\n")
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_multisource_slice.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/data/lanl_slice.py apps/api/tests/test_multisource_slice.py
git commit -m "feat(data): host-scoped multi-source line filter"
```

---

### Task 4: Real multi-source incident builder + run

**Files:**
- Create: `apps/api/prahari/data/multisource.py`
- Create: `apps/api/tests/test_multisource_build.py`
- Create: `apps/api/scripts/run_multisource_incident.py`
- Create: `docs/benchmarks/lanl-multisource-results.md`

**Interfaces:**
- Consumes: parsers, `enrich`, `correlate`, `target_of`, `Incident`.
- Produces:
  - `build_incidents(auth_lines, proc_lines, flow_lines, redteam, window_seconds=600) -> list[Incident]` — parses each source (auth labelled via `redteam`), enriches, correlates by `target_of`, returns incidents sorted by compound desc.
  - The runner slices the real gzip files for the red-team hosts in a window and prints the fused incident(s); results recorded honestly.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_multisource_build.py`:
```python
from prahari.data.multisource import build_incidents


def test_build_fuses_three_sources_on_one_host():
    auth = ["150885,U620@DOM1,U620@DOM1,C17693,C1003,NTLM,Network,LogOn,Success"]
    proc = ["150900,U620@DOM1,C1003,P7,Start"]
    flow = ["151000,3,C1003,N93,C5074,443,6,10,4200"]
    redteam = {("150885", "U620@DOM1", "C17693", "C1003")}

    incidents = build_incidents(auth, proc, flow, redteam, window_seconds=600)
    c1003 = next(i for i in incidents if i.entity == "C1003")

    assert len(c1003.sources) == 3            # lanl + lanl_proc + lanl_flow
    assert len(c1003.phases) == 3             # lateral + execution + c2
    assert c1003.high_confidence is True
    assert c1003.is_true_positive is True     # red-team auth carried the label
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_multisource_build.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.data.multisource'`

- [ ] **Step 3: Implement the builder**

`apps/api/prahari/data/multisource.py`:
```python
from __future__ import annotations

from prahari.correlate.correlator import correlate
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import target_of
from prahari.enrich import enrich
from prahari.parsers.lanl import (
    parse_lanl_flow_line, parse_lanl_line, parse_lanl_proc_line,
)


def build_incidents(
    auth_lines: list[str],
    proc_lines: list[str],
    flow_lines: list[str],
    redteam: set[tuple[str, str, str, str]],
    window_seconds: float = 600,
) -> list[Incident]:
    events = [parse_lanl_line(ln, redteam) for ln in auth_lines if ln.strip()]
    for ln in proc_lines:
        if ln.strip():
            ev = parse_lanl_proc_line(ln)
            if ev is not None:
                events.append(ev)
    events += [parse_lanl_flow_line(ln) for ln in flow_lines if ln.strip()]

    events = [enrich(e) for e in events]
    return correlate(events, key_fn=target_of, window_seconds=window_seconds)
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_multisource_build.py -v`
Expected: PASS

- [ ] **Step 5: Write the runner script**

`apps/api/scripts/run_multisource_incident.py`:
```python
"""Build a real multi-source incident from LANL auth+proc+flows for red-team hosts.
Manual (multi-GB): not in CI.

Usage: cd apps/api && PYTHONPATH=. uv run python scripts/run_multisource_incident.py [T0] [T1]
"""
from __future__ import annotations

import gzip
import sys
from pathlib import Path

from prahari.data.lanl_slice import lines_for_hosts, slice_auth_lines
from prahari.data.multisource import build_incidents

ROOT = Path(__file__).resolve().parents[3]


def load_redteam(t0: int, t1: int):
    keys = set(); hosts = set()
    with gzip.open(ROOT / "data/redteam.txt.gz", "rt") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            t, u, s, d = line.split(",")
            if t0 <= int(t) < t1:
                keys.add((t, u, s, d)); hosts.update({s, d})
    return keys, hosts


def _slice(path, hosts, t0, t1, host_fields):
    with gzip.open(ROOT / path, "rt") as fh:
        return list(lines_for_hosts(fh, hosts, t0, t1, host_fields))


def main() -> None:
    t0 = int(sys.argv[1]) if len(sys.argv) > 1 else 150000
    t1 = int(sys.argv[2]) if len(sys.argv) > 2 else 160000
    redteam, hosts = load_redteam(t0, t1)
    print(f"window [{t0},{t1}): {len(redteam)} red-team events, {len(hosts)} hosts")

    with gzip.open(ROOT / "data/auth.txt.gz", "rt") as fh:
        auth = [ln for ln in slice_auth_lines(fh, t0, t1)
                if (p := ln.split(",")) and len(p) >= 5 and (p[3] in hosts or p[4] in hosts)]
    proc = _slice("data/proc.txt.gz", hosts, t0, t1, (2,))
    flow = _slice("data/flows.txt.gz", hosts, t0, t1, (2, 4))
    print(f"sliced: auth={len(auth)} proc={len(proc)} flow={len(flow)}")

    incidents = build_incidents(auth, proc, flow, redteam, window_seconds=600)
    hc = [i for i in incidents if i.high_confidence]
    tp = [i for i in hc if i.is_true_positive]
    print(f"incidents={len(incidents)} high_confidence={len(hc)} of-which-red-team={len(tp)}")

    for inc in sorted(tp, key=lambda i: i.compound_score, reverse=True)[:3]:
        print(f"\n=== {inc.entity}  compound={inc.compound_score:.2f}  "
              f"sources={sorted(inc.sources)} phases={sorted(inc.phases)} ===")
        for e in inc.timeline()[:12]:
            print(f"  {e.timestamp:%H:%M:%S} {e.event_type:13s} {e.source:10s} "
                  f"{(e.source_entity or ''):16s} -> {e.dest_entity or e.dst_host or e.dst_ip or ''}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Run it on the real data**

Run: `cd apps/api && PYTHONPATH=. uv run python scripts/run_multisource_incident.py 150000 160000`
Expected: prints slice sizes and at least one high-confidence red-team incident with 2–3 sources. **Record the actual output.** If no host reaches 3 sources, report honestly what fused (auth+proc on the victim; flows on the foothold) and widen the window or pick another red-team host — do not fake a 3-source incident.

- [ ] **Step 7: Record results + full suite (Phase 3.5 exit gate)**

Create `docs/benchmarks/lanl-multisource-results.md` with the **actual** fused timeline and counts, and an honest read: how many red-team hosts fused ≥2 sources, whether high_confidence separated them from benign, and that this is the real-data version of the C553 moment.

Run: `cd apps/api && uv run pytest -q`
Expected: PASS — all prior + new parser/slice/build tests green.

- [ ] **Step 8: Commit**

```bash
git add apps/api/prahari/data/multisource.py apps/api/tests/test_multisource_build.py apps/api/scripts/run_multisource_incident.py docs/benchmarks/lanl-multisource-results.md
git commit -m "feat(data): real LANL multi-source incident builder + recorded results"
```

---

## Self-Review

**Spec coverage (Phase 3.5):**
- Real cross-source fusion on LANL (spec §3, §6, differentiator #3) → Tasks 1–4 ✅
- Proves `high_confidence` (≥2 sources, ≥2 phases) on real data → Task 4 ✅
- The real-data C553 moment → Task 4 runner ✅
- Deferred (correct/honest): per-source anomaly scoring for proc/flow (would give precision-at-scale — a larger future lift); dashboard serving the real incident (optional follow-up).

**Placeholder scan:** No TBD/TODO. Task 6/7 record *actual* runtime output with an explicit honesty instruction, not placeholders.

**Type consistency:** `parse_lanl_proc_line`/`parse_lanl_flow_line` (Tasks 1–2) reused by `build_incidents` (Task 4). `lines_for_hosts(lines, hosts, t0, t1, host_fields)` (Task 3) used in the runner (Task 4). `build_incidents(auth_lines, proc_lines, flow_lines, redteam, window_seconds)` identical in Task 4 test/impl and runner. Sources `lanl`/`lanl_proc`/`lanl_flow` consistent so `len(sources)` counts fusion. `target_of` mapping (auth→dst_host, proc/flow→src_host) matches the parser field assignments.
