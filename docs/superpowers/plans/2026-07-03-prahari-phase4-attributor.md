# Prahari Phase 4 (Attributor): MITRE ATT&CK RAG + Predictor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Map a correlated Incident to MITRE ATT&CK techniques with cited, grounded reasoning (RAG over the ATT&CK corpus via Ollama), and predict the likely next tactic — turning a raw incident into an explained, framework-mapped intelligence report.

**Architecture:** Deterministic retrieval + guarded LLM reasoning. An `AttackCorpus` of ATT&CK technique docs is embedded once (local `embeddinggemma` via Ollama) into an in-memory numpy matrix — no vector DB needed for ~700 docs. A `Retriever` does cosine top-k. The `Attributor` sends the incident + retrieved techniques to a reasoning model (`qwen3.5:cloud`), parses structured output, and **constrains cited technique IDs to the retrieved set** (hallucination guard). A `TacticPredictor` learns an ATT&CK tactic transition matrix (Markov) and ranks next tactics. All LLM/embedding calls are injected as functions so unit tests are deterministic and offline; thin Ollama adapters + a live demo script wire the real models.

**Tech Stack:** Python 3.14 + uv, numpy, httpx (Ollama HTTP). Ollama models confirmed present: `embeddinggemma:latest` (local, 768-dim embeddings), `qwen3.5:cloud` (reasoning). Builds on Phase 3 `Incident`.

## Global Constraints

- Package root `apps/api`, package `prahari`; tests: `cd apps/api && uv run pytest`.
- **Unit tests never call Ollama or the network.** Embedding/chat are injected `Callable`s; tests pass fakes. Live model use is confined to `prahari/attribute/ollama.py` (thin adapter) and `scripts/run_attribution_demo.py` (manual).
- **Hallucination guard is mandatory:** the Attributor may only cite technique IDs that were in the retrieved set; any other ID the model returns is dropped.
- Embeddings model `embeddinggemma`, reasoning model `qwen3.5:cloud`, Ollama host `http://localhost:11434`. Local embeddings keep the sovereign story; reasoning can be pointed at a local model too.
- Derived ATT&CK corpus is committed at `corpus/attack_techniques.json` (built from STIX by a script; the 35MB STIX is not committed).
- Commit after every task with the message in its final step.

---

### Task 1: AttackCorpus loader + technique doc + build script

**Files:**
- Create: `apps/api/prahari/attribute/__init__.py`
- Create: `apps/api/prahari/attribute/corpus.py`
- Create: `apps/api/tests/fixtures/attack_mini.json`
- Create: `apps/api/tests/test_corpus.py`
- Create: `apps/api/scripts/build_attack_corpus.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `@dataclass TechniqueDoc` with `id: str`, `name: str`, `tactics: list[str]`, `description: str`, and `text() -> str` (retrieval text: `"<id> <name>. Tactics: <t1, t2>. <description>"`).
  - `load_corpus(path: str | Path) -> list[TechniqueDoc]` — reads a derived JSON array of `{id, name, tactics, description}`.
  - `scripts/build_attack_corpus.py` — downloads enterprise-attack STIX, extracts `attack-pattern` objects (skips revoked/deprecated), writes `corpus/attack_techniques.json`.

- [ ] **Step 1: Create the fixture**

`apps/api/tests/fixtures/attack_mini.json`:
```json
[
  {"id": "T1021", "name": "Remote Services", "tactics": ["lateral-movement"], "description": "Adversaries may use valid accounts to log into remote services such as SMB or RDP."},
  {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "description": "Adversaries may abuse command interpreters like cmd or PowerShell to execute commands."},
  {"id": "T1071", "name": "Application Layer Protocol", "tactics": ["command-and-control"], "description": "Adversaries may communicate using application layer protocols such as HTTPS to blend with normal traffic."}
]
```

- [ ] **Step 2: Write the failing test**

`apps/api/tests/test_corpus.py`:
```python
from pathlib import Path

from prahari.attribute.corpus import TechniqueDoc, load_corpus

FIX = Path(__file__).parent / "fixtures"


def test_load_corpus_and_text():
    docs = load_corpus(FIX / "attack_mini.json")
    assert len(docs) == 3
    t1021 = next(d for d in docs if d.id == "T1021")
    assert isinstance(t1021, TechniqueDoc)
    assert t1021.name == "Remote Services"
    assert t1021.tactics == ["lateral-movement"]
    assert "T1021" in t1021.text()
    assert "lateral-movement" in t1021.text()
    assert "remote services" in t1021.text().lower()
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_corpus.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.attribute'`

- [ ] **Step 4: Implement loader + build script**

`apps/api/prahari/attribute/__init__.py`: (empty file)

`apps/api/prahari/attribute/corpus.py`:
```python
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TechniqueDoc:
    id: str
    name: str
    tactics: list[str]
    description: str

    def text(self) -> str:
        tac = ", ".join(self.tactics)
        return f"{self.id} {self.name}. Tactics: {tac}. {self.description}"


def load_corpus(path: str | Path) -> list[TechniqueDoc]:
    raw = json.loads(Path(path).read_text())
    return [
        TechniqueDoc(
            id=d["id"], name=d["name"],
            tactics=list(d.get("tactics", [])), description=d.get("description", ""),
        )
        for d in raw
    ]
```

`apps/api/scripts/build_attack_corpus.py`:
```python
"""Build the trimmed ATT&CK technique corpus from MITRE STIX. Manual (network).

Usage: cd apps/api && uv run python scripts/build_attack_corpus.py
Writes corpus/attack_techniques.json (committed).
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[3]
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def main() -> None:
    data = httpx.get(STIX_URL, timeout=120, follow_redirects=True).json()
    out = []
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext or not ext.get("external_id", "").startswith("T"):
            continue
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        desc = (obj.get("description") or "").split("\n")[0][:600]
        out.append({
            "id": ext["external_id"], "name": obj.get("name", ""),
            "tactics": tactics, "description": desc,
        })
    out.sort(key=lambda d: d["id"])
    dest = ROOT / "corpus/attack_techniques.json"
    dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps(out, indent=1))
    print(f"wrote {len(out)} techniques to {dest}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_corpus.py -v`
Expected: PASS

- [ ] **Step 6: Build the real corpus and commit it**

Run: `cd apps/api && uv run python scripts/build_attack_corpus.py`
Expected: prints `wrote <~650> techniques to .../corpus/attack_techniques.json`

- [ ] **Step 7: Commit**

```bash
git add apps/api/prahari/attribute/__init__.py apps/api/prahari/attribute/corpus.py apps/api/scripts/build_attack_corpus.py apps/api/tests/test_corpus.py apps/api/tests/fixtures/attack_mini.json corpus/attack_techniques.json
git commit -m "feat(attribute): ATT&CK corpus loader + build script + derived corpus"
```

---

### Task 2: Retriever (embed + cosine top-k)

**Files:**
- Create: `apps/api/prahari/attribute/retriever.py`
- Create: `apps/api/tests/test_retriever.py`

**Interfaces:**
- Consumes: `TechniqueDoc`.
- Produces:
  - `class Retriever(embed_fn: Callable[[list[str]], np.ndarray])` where `embed_fn` maps texts → an `(n, dim)` float array.
  - `fit(corpus: list[TechniqueDoc]) -> Retriever` — embeds and L2-normalises corpus texts.
  - `retrieve(query: str, k: int = 5) -> list[tuple[TechniqueDoc, float]]` — cosine similarity, top-k descending.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_retriever.py`:
```python
import numpy as np

from prahari.attribute.corpus import TechniqueDoc
from prahari.attribute.retriever import Retriever

CORPUS = [
    TechniqueDoc("T1021", "Remote Services", ["lateral-movement"], "log into remote services"),
    TechniqueDoc("T1059", "Command and Scripting", ["execution"], "execute commands via shell"),
    TechniqueDoc("T1071", "Application Layer Protocol", ["command-and-control"], "https beacon traffic"),
]

# deterministic fake embeddings: keyword -> one-hot axis
_VOCAB = ["remote", "execute", "beacon"]


def _fake_embed(texts):
    vecs = []
    for t in texts:
        low = t.lower()
        vecs.append([1.0 if w in low else 0.0 for w in _VOCAB])
    return np.array(vecs, dtype=float)


def test_retrieve_ranks_by_cosine():
    r = Retriever(embed_fn=_fake_embed).fit(CORPUS)
    hits = r.retrieve("suspicious remote login", k=2)
    assert hits[0][0].id == "T1021"        # "remote" axis
    assert len(hits) == 2
    assert hits[0][1] >= hits[1][1]        # sorted by score desc


def test_retrieve_execution_query():
    r = Retriever(embed_fn=_fake_embed).fit(CORPUS)
    hits = r.retrieve("execute a command", k=1)
    assert hits[0][0].id == "T1059"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_retriever.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.attribute.retriever'`

- [ ] **Step 3: Implement**

`apps/api/prahari/attribute/retriever.py`:
```python
from __future__ import annotations

from collections.abc import Callable

import numpy as np

from prahari.attribute.corpus import TechniqueDoc


def _l2norm(m: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return m / norms


class Retriever:
    def __init__(self, embed_fn: Callable[[list[str]], np.ndarray]) -> None:
        self.embed_fn = embed_fn
        self.corpus: list[TechniqueDoc] = []
        self._matrix = np.empty((0, 0))

    def fit(self, corpus: list[TechniqueDoc]) -> "Retriever":
        self.corpus = list(corpus)
        embeddings = np.asarray(self.embed_fn([d.text() for d in self.corpus]), dtype=float)
        self._matrix = _l2norm(embeddings)
        return self

    def retrieve(self, query: str, k: int = 5) -> list[tuple[TechniqueDoc, float]]:
        q = np.asarray(self.embed_fn([query]), dtype=float)
        q = _l2norm(q)[0]
        scores = self._matrix @ q
        order = np.argsort(scores)[::-1][:k]
        return [(self.corpus[i], float(scores[i])) for i in order]
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_retriever.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/attribute/retriever.py apps/api/tests/test_retriever.py
git commit -m "feat(attribute): embedding retriever with cosine top-k"
```

---

### Task 3: Attributor (RAG reasoning + hallucination guard)

**Files:**
- Create: `apps/api/prahari/attribute/attributor.py`
- Create: `apps/api/tests/test_attributor.py`

**Interfaces:**
- Consumes: `Retriever`, `TechniqueDoc`, `Incident` (Phase 3).
- Produces:
  - `@dataclass Attribution` with `technique_ids: list[str]`, `explanation: str`, `retrieved_ids: list[str]`.
  - `summarize_incident(incident: Incident) -> str` — a text description (entity, phases, per-event one-liners) used as the retrieval + reasoning query.
  - `class Attributor(retriever: Retriever, chat_fn: Callable[[str], str], k: int = 5)` with `attribute(incident: Incident) -> Attribution`. It retrieves top-k techniques, prompts `chat_fn` for a JSON object `{"technique_ids": [...], "explanation": "..."}`, parses it, and **drops any technique_id not in the retrieved set** (hallucination guard).

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_attributor.py`:
```python
from datetime import datetime, timezone

import numpy as np

from prahari.attribute.attributor import Attributor, summarize_incident
from prahari.attribute.corpus import TechniqueDoc
from prahari.attribute.retriever import Retriever
from prahari.correlate.incident import Incident
from prahari.schema import CanonicalEvent

CORPUS = [
    TechniqueDoc("T1021", "Remote Services", ["lateral-movement"], "remote login smb rdp"),
    TechniqueDoc("T1059", "Command and Scripting", ["execution"], "execute command shell whoami"),
    TechniqueDoc("T1071", "Application Layer Protocol", ["command-and-control"], "https beacon outbound"),
]
_VOCAB = ["remote", "whoami", "beacon", "lateral", "execute", "outbound"]


def _fake_embed(texts):
    return np.array([[1.0 if w in t.lower() else 0.0 for w in _VOCAB] for t in texts], dtype=float)


def _incident():
    def ev(sec, et, src, **kw):
        return CanonicalEvent(timestamp=datetime(2017, 7, 5, 15, 32, sec, tzinfo=timezone.utc),
                              event_type=et, source=src, raw="x", **kw)
    return Incident(entity="C553", events=[
        ev(16, "auth", "lanl", source_entity="U342", dst_host="C553", asset_criticality="critical"),
        ev(19, "process", "otrf", source_entity="U342", src_host="C553", dest_entity="cmd /c whoami"),
        ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17"),
    ])


def test_summarize_incident_mentions_entity_and_phases():
    s = summarize_incident(_incident())
    assert "C553" in s
    assert "lateral_movement" in s
    assert "whoami" in s


def test_attributor_parses_and_guards_hallucinations():
    # model returns one real retrieved id plus one hallucinated id (T9999)
    def fake_chat(prompt: str) -> str:
        return '{"technique_ids": ["T1021", "T9999"], "explanation": "lateral movement then recon"}'

    retriever = Retriever(embed_fn=_fake_embed).fit(CORPUS)
    attr = Attributor(retriever, chat_fn=fake_chat, k=3).attribute(_incident())

    assert "T1021" in attr.technique_ids
    assert "T9999" not in attr.technique_ids   # hallucination dropped
    assert set(attr.technique_ids) <= set(attr.retrieved_ids)
    assert "lateral movement" in attr.explanation
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_attributor.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.attribute.attributor'`

- [ ] **Step 3: Implement**

`apps/api/prahari/attribute/attributor.py`:
```python
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from prahari.attribute.retriever import Retriever
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import killchain_phase


@dataclass
class Attribution:
    technique_ids: list[str]
    explanation: str
    retrieved_ids: list[str]


def summarize_incident(incident: Incident) -> str:
    lines = [f"Incident on entity {incident.entity}. "
             f"Phases: {', '.join(sorted(incident.phases))}. Timeline:"]
    for e in incident.timeline():
        phase = killchain_phase(e)
        detail = e.dest_entity or e.dst_host or e.dst_ip or ""
        lines.append(f"- {e.event_type} {phase}: {e.source_entity or ''} -> {detail}")
    return "\n".join(lines)


_PROMPT = """You are a SOC analyst. Given an incident and candidate MITRE ATT&CK techniques,
choose the techniques that apply and explain briefly. Respond ONLY as JSON:
{{"technique_ids": ["T####", ...], "explanation": "..."}}
Use only technique IDs from the candidates.

INCIDENT:
{summary}

CANDIDATE TECHNIQUES:
{candidates}
"""


class Attributor:
    def __init__(self, retriever: Retriever, chat_fn: Callable[[str], str], k: int = 5) -> None:
        self.retriever = retriever
        self.chat_fn = chat_fn
        self.k = k

    def attribute(self, incident: Incident) -> Attribution:
        summary = summarize_incident(incident)
        hits = self.retriever.retrieve(summary, k=self.k)
        retrieved_ids = [doc.id for doc, _ in hits]
        candidates = "\n".join(f"{doc.id} {doc.name}: {doc.description}" for doc, _ in hits)
        raw = self.chat_fn(_PROMPT.format(summary=summary, candidates=candidates))

        parsed = _parse_json(raw)
        allowed = set(retrieved_ids)
        ids = [tid for tid in parsed.get("technique_ids", []) if tid in allowed]
        return Attribution(
            technique_ids=ids,
            explanation=str(parsed.get("explanation", "")),
            retrieved_ids=retrieved_ids,
        )


def _parse_json(raw: str) -> dict:
    start, end = raw.find("{"), raw.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            pass
    return {}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_attributor.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/attribute/attributor.py apps/api/tests/test_attributor.py
git commit -m "feat(attribute): Attributor RAG reasoning with hallucination guard"
```

---

### Task 4: TacticPredictor (Markov next-tactic)

**Files:**
- Create: `apps/api/prahari/attribute/predictor.py`
- Create: `apps/api/tests/test_predictor.py`

**Interfaces:**
- Consumes: nothing (operates on tactic-name strings).
- Produces:
  - `class TacticPredictor` with `fit(sequences: list[list[str]]) -> TacticPredictor` (counts tactic→next-tactic transitions) and `predict_next(current: str, k: int = 3) -> list[tuple[str, float]]` (probabilities, descending). Unknown `current` returns `[]`.
  - `ATTACK_TACTIC_PRIOR: list[list[str]]` — a small curated set of typical kill-chain tactic orderings to seed the model when real sequences are scarce.

- [ ] **Step 1: Write the failing test**

`apps/api/tests/test_predictor.py`:
```python
from prahari.attribute.predictor import TacticPredictor


def test_predict_next_from_sequences():
    seqs = [
        ["lateral-movement", "discovery", "command-and-control"],
        ["lateral-movement", "discovery", "collection"],
        ["lateral-movement", "execution", "discovery"],
    ]
    p = TacticPredictor().fit(seqs)
    nxt = p.predict_next("lateral-movement", k=2)
    # after lateral-movement: discovery (2/3) beats execution (1/3)
    assert nxt[0][0] == "discovery"
    assert nxt[0][1] > nxt[1][1]


def test_predict_unknown_returns_empty():
    p = TacticPredictor().fit([["a", "b"]])
    assert p.predict_next("zzz") == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_predictor.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'prahari.attribute.predictor'`

- [ ] **Step 3: Implement**

`apps/api/prahari/attribute/predictor.py`:
```python
from __future__ import annotations

from collections import Counter, defaultdict

ATTACK_TACTIC_PRIOR = [
    ["initial-access", "execution", "discovery", "lateral-movement",
     "collection", "command-and-control", "exfiltration"],
    ["lateral-movement", "discovery", "collection", "exfiltration"],
    ["execution", "discovery", "lateral-movement", "command-and-control"],
]


class TacticPredictor:
    def __init__(self) -> None:
        self._trans: dict[str, Counter] = defaultdict(Counter)

    def fit(self, sequences: list[list[str]]) -> "TacticPredictor":
        for seq in sequences:
            for a, b in zip(seq, seq[1:]):
                self._trans[a][b] += 1
        return self

    def predict_next(self, current: str, k: int = 3) -> list[tuple[str, float]]:
        counts = self._trans.get(current)
        if not counts:
            return []
        total = sum(counts.values())
        ranked = counts.most_common(k)
        return [(tactic, n / total) for tactic, n in ranked]
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_predictor.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add apps/api/prahari/attribute/predictor.py apps/api/tests/test_predictor.py
git commit -m "feat(attribute): Markov tactic predictor"
```

---

### Task 5: Ollama adapters + live attribution demo

**Files:**
- Create: `apps/api/prahari/attribute/ollama.py`
- Create: `apps/api/scripts/run_attribution_demo.py`
- Create: `docs/benchmarks/attribution-demo.md`

**Interfaces:**
- Consumes: `load_corpus`, `Retriever`, `Attributor`, `TacticPredictor`, `Incident`.
- Produces:
  - `ollama_embed(texts: list[str], model="embeddinggemma", host="http://localhost:11434") -> np.ndarray` — POST `/api/embed`, returns `(n, dim)`.
  - `ollama_chat(prompt: str, model="qwen3.5:cloud", host="http://localhost:11434") -> str` — POST `/api/chat` (`stream=false`), returns message content.
  - `scripts/run_attribution_demo.py` — builds the C553 incident, embeds the real corpus, attributes via real Ollama, prints techniques + explanation + predicted next tactic.

- [ ] **Step 1: Implement the Ollama adapters**

`apps/api/prahari/attribute/ollama.py`:
```python
"""Thin Ollama HTTP adapters. Not unit-tested (require the live daemon)."""
from __future__ import annotations

import httpx
import numpy as np

DEFAULT_HOST = "http://localhost:11434"


def ollama_embed(
    texts: list[str], model: str = "embeddinggemma", host: str = DEFAULT_HOST
) -> np.ndarray:
    resp = httpx.post(f"{host}/api/embed", json={"model": model, "input": texts}, timeout=120)
    resp.raise_for_status()
    return np.array(resp.json()["embeddings"], dtype=float)


def ollama_chat(
    prompt: str, model: str = "qwen3.5:cloud", host: str = DEFAULT_HOST
) -> str:
    resp = httpx.post(
        f"{host}/api/chat",
        json={"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False},
        timeout=180,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]
```

- [ ] **Step 2: Write the live demo script**

`apps/api/scripts/run_attribution_demo.py`:
```python
"""Live ATT&CK attribution on the C553 incident. Manual (Ollama): not in CI.

Usage: cd apps/api && PYTHONPATH=. uv run python scripts/run_attribution_demo.py
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from prahari.attribute.attributor import Attributor, summarize_incident
from prahari.attribute.corpus import load_corpus
from prahari.attribute.ollama import ollama_chat, ollama_embed
from prahari.attribute.predictor import ATTACK_TACTIC_PRIOR, TacticPredictor
from prahari.attribute.retriever import Retriever
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import killchain_phase
from prahari.schema import CanonicalEvent

ROOT = Path(__file__).resolve().parents[3]


def _c553_incident() -> Incident:
    def ev(sec, et, src, **kw):
        return CanonicalEvent(timestamp=datetime(2017, 7, 5, 15, 32, sec, tzinfo=timezone.utc),
                              event_type=et, source=src, raw="x", **kw)
    return Incident(entity="C553", events=[
        ev(16, "auth", "lanl", source_entity="U342@DOM1", dst_host="C553", auth_type="NTLM",
           asset_criticality="critical", labels=["redteam"]),
        ev(19, "process", "otrf", source_entity="U342@DOM1", src_host="C553", dest_entity="cmd /c whoami"),
        ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17"),
    ])


def main() -> None:
    corpus = load_corpus(ROOT / "corpus/attack_techniques.json")
    print(f"corpus: {len(corpus)} techniques; embedding with embeddinggemma...")
    retriever = Retriever(embed_fn=ollama_embed).fit(corpus)

    incident = _c553_incident()
    print("\n--- INCIDENT SUMMARY ---")
    print(summarize_incident(incident))

    attribution = Attributor(retriever, chat_fn=ollama_chat, k=6).attribute(incident)
    print("\n--- ATT&CK ATTRIBUTION (grounded) ---")
    print("techniques:", attribution.technique_ids)
    print("retrieved :", attribution.retrieved_ids)
    print("explanation:", attribution.explanation)

    predictor = TacticPredictor().fit(ATTACK_TACTIC_PRIOR)
    last_phase = killchain_phase(incident.timeline()[-1])
    tactic = {"command_and_control": "command-and-control", "discovery": "discovery",
              "lateral_movement": "lateral-movement", "execution": "execution"}.get(last_phase, last_phase)
    print("\n--- PREDICTED NEXT TACTIC ---")
    print(f"after {tactic}:", predictor.predict_next(tactic, k=3))


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Run the live demo**

Run: `cd apps/api && PYTHONPATH=. uv run python scripts/run_attribution_demo.py`
Expected: prints the incident summary, grounded technique IDs (should include lateral-movement / execution / C2 techniques like T1021 / T1059 / T1071), an explanation, and a predicted next tactic. **Record the actual output.** If the reasoning model returns non-JSON or empty techniques, note it and (a) retry with `deepseek-v3.2:cloud`, or (b) tighten the prompt — do not fake the output.

- [ ] **Step 4: Record the demo output**

Create `docs/benchmarks/attribution-demo.md` with the **actual** printed attribution (techniques, explanation, predicted next tactic), the models used (embeddinggemma + qwen3.5), and one line noting the hallucination guard dropped/kept which IDs.

- [ ] **Step 5: Run the full suite (Phase 4 exit gate)**

Run: `cd apps/api && uv run pytest -q`
Expected: PASS — all prior tests + corpus/retriever/attributor/predictor green.

- [ ] **Step 6: Commit**

```bash
git add apps/api/prahari/attribute/ollama.py apps/api/scripts/run_attribution_demo.py docs/benchmarks/attribution-demo.md
git commit -m "feat(attribute): Ollama adapters + live attribution demo"
```

---

## Self-Review

**Spec coverage (Attributor scope):**
- RAG over ATT&CK via Ollama, cited techniques (spec §7, differentiator #1/Innovation) → Tasks 1–3, 5 ✅
- Hallucination guard: IDs constrained to retrieved set (spec §7) → Task 3 ✅
- Local/sovereign embeddings (spec §15) → `embeddinggemma`, Task 5 ✅
- Next-step prediction, explicit/testable (spec §8) → Task 4 ✅
- Deferred (correct): CERT-In advisories in corpus (add later as extra docs), Sigma rules, dashboard rendering (Phase B), wiring Attributor onto real correlated incidents.

**Placeholder scan:** No TBD/TODO. Task 5 Step 3/4 record *actual* live model output (can't be pre-written) and instruct honesty on failure — real instructions, not placeholders.

**Type consistency:** `TechniqueDoc.text()` used by `Retriever.fit` (Task 2) and shown in `Attributor` candidates (Task 3). `Retriever(embed_fn).fit(corpus).retrieve(query,k) -> list[tuple[TechniqueDoc,float]]` identical across Tasks 2,3,5. `Attributor(retriever, chat_fn, k).attribute(incident) -> Attribution` identical in Task 3 test/impl and Task 5 demo. `embed_fn: Callable[[list[str]], np.ndarray]` and `chat_fn: Callable[[str], str]` signatures match the Ollama adapters `ollama_embed`/`ollama_chat` (Task 5). `summarize_incident(incident) -> str` consistent. `TacticPredictor().fit(sequences).predict_next(current,k)` consistent Task 4/5.

**Risk note:** Task 5 is empirical (live LLM). If `qwen3.5:cloud` output is unreliable JSON, the guard still yields a safe (possibly empty) `technique_ids`; the plan says retry with `deepseek-v3.2` or tighten the prompt rather than fabricate. Retrieval (deterministic) still gives the top techniques even if reasoning is weak.
