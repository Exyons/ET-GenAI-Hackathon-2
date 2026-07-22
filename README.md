# Prahari

**AI-Driven Cyber Resilience for Critical National Infrastructure**

ET AI Hackathon 2026 · Problem Statement 7

Prahari detects threats by how systems behave abnormally, not by matching known malware signatures. It fuses authentication, network, and endpoint telemetry into a single incident timeline, maps the intrusion to MITRE ATT&CK with cited reasoning, and runs fully air-gapped for sovereign deployment on classified networks.

---

## Why Prahari

Signature-based tools miss advanced persistent threats that use valid credentials. On real LANL red-team data, signature detection scores 0.00 recall. Prahari's behavioural approach scores 0.79 recall on the same data. The key insight: precision is not a threshold problem, it is a fusion problem. Single-source detection is noisy; cross-source correlation is where precision comes from.

## How It Works

Prahari runs a five-stage intelligence pipeline:

```
Raw Telemetry → Ingestion → Anomaly Detection → Correlation → Attribution → Response
                                        ↓                ↓              ↓
                                  Isolation Forest   Kill-chain     MITRE ATT&CK
                                  + UEBA novelty     + compound     via local LLM
                                  scoring            scoring        (air-gapped)
```

1. **Ingestion & Normalisation** — Parse heterogeneous telemetry (auth logs, process events, network flows) into a unified `CanonicalEvent` schema.

2. **Behavioural Anomaly Detection** — Score deviations from per-entity baselines using an ensemble of Isolation Forest and novelty scoring (UEBA).

3. **Cross-Source Correlation** — Fuse anomalous events across telemetry sources into compound incidents with kill-chain phase labels. High-confidence incidents require 2+ sources and 2+ phases.

4. **MITRE ATT&CK Attribution** — Map incidents to ATT&CK techniques using grounded RAG with local LLMs. A hallucination guard ensures only retrieved technique IDs are cited.

5. **Response Orchestration** — Recommend containment actions behind a human-approval gate.

Detection and correlation run on real ML. The LLM only reasons and explains.

## Results

| Metric | Result |
|---|---|
| Behavioural recall (LANL) | **0.79** vs 0.00 for signatures |
| Multi-source fusion | **9/11** red-team hosts fused into high-confidence incidents |
| ATT&CK attribution | T1021.006, T1057, T1071.002 (all verified against corpus) |
| Air-gap | Zero cloud API calls, zero network egress |

## Quick Start

### Prerequisites

- Python 3.14+ with [uv](https://docs.astral.sh/uv/)
- Node.js 18+
- [Ollama](https://ollama.com) (for LLM attribution)

### 1. Clone and configure

```bash
git clone https://github.com/Exyons/ET-GenAI-Hackathon-2.git
cd ET-GenAI-Hackathon-2
cp .env.example .env
```

### 2. Pull LLM models (air-gapped, one-time)

```bash
ollama pull qwen2.5:7b
ollama pull embeddinggemma
```

### 3. Run with Docker Compose

```bash
docker-compose up
```

This starts:
- **API** on `http://localhost:8000`
- **Dashboard** on `http://localhost:3000`
- **ChromaDB** on `http://localhost:8001`
- **Ollama** on `http://localhost:11434`

### 4. Or run locally (development)

```bash
# API
cd apps/api
uv sync
uv run uvicorn prahari_api:app --reload --port 8000

# Dashboard
cd apps/web
npm install
npm run dev
```

## Project Structure

```
.
├── apps/
│   ├── api/                  # FastAPI backend
│   │   └── prahari/
│   │       ├── schema.py             # CanonicalEvent model
│   │       ├── parsers/              # LANL, CICIDS, Sysmon parsers
│   │       ├── detect/               # Anomaly detection (Sentinel, NetworkSentinel)
│   │       ├── correlate/            # Kill-chain tagging, incident scoring
│   │       ├── attribute/            # RAG attribution (corpus, retriever, LLM)
│   │       ├── live/                 # Live pipeline, EventBus, playbooks
│   │       └── api/                  # FastAPI routes, serializers
│   └── web/                  # Next.js SOC command dashboard
├── collectors/                # Telemetry collector agents (Linux/Windows)
├── corpus/                    # ATT&CK technique corpus (697 techniques)
├── data/                      # Dataset download scripts (raw data git-ignored)
├── threatintel/               # CERT-In advisories, threat intelligence
├── docker-compose.yml
└── .env.example
```

## Tech Stack

| Layer | Technology |
|---|---|
| Detection | scikit-learn Isolation Forest + novelty scoring (UEBA) |
| Attribution | Ollama (local) + numpy cosine retrieval |
| Correlation | Kill-chain tagging + compound scoring |
| Backend | FastAPI + Pydantic |
| Frontend | Next.js (App Router) + React |
| Deploy | docker-compose, SOVEREIGN_MODE |
| Collector | Python stdlib only (no pip on monitored VMs) |

## Configuration

Key environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `PRAHARI_INGEST_TOKEN` | `dev-token` | Bearer token for collector auth |
| `WARMUP_SECONDS` | `180` | Duration to learn normal behaviour |
| `CORR_WINDOW_SECONDS` | `300` | Correlation sliding window |
| `ANOMALY_QUANTILE` | `0.99` | Threshold quantile on warmup scores |
| `PRAHARI_CHAT_MODEL` | `qwen2.5:7b` | LLM for ATT&CK explanation |
| `PRAHARI_EMBED_MODEL` | `embeddinggemma` | Embeddings for technique retrieval |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |

## Testing

```bash
cd apps/api && uv run pytest -v
```

54 test files covering unit tests, integration tests, live pipeline tests, API route tests, and attribution tests. All tests run with deterministic fixtures and no Ollama calls in CI.


