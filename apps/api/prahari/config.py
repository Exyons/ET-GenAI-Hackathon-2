from __future__ import annotations

import os
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]

# Live pipeline / ingest configuration. Plain env reads — no new deps.
INGEST_TOKEN = os.environ.get("PRAHARI_INGEST_TOKEN", "dev-token")
WARMUP_SECONDS = int(os.environ.get("WARMUP_SECONDS", "180"))
CORR_WINDOW_SECONDS = int(os.environ.get("CORR_WINDOW_SECONDS", "300"))
ANOMALY_QUANTILE = float(os.environ.get("ANOMALY_QUANTILE", "0.99"))
STATE_DIR = os.environ.get("STATE_DIR", "./state")

# Attribution (local, air-gapped by default)
CHAT_MODEL = os.environ.get("PRAHARI_CHAT_MODEL", "qwen2.5:7b")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
CORPUS_PATH = os.environ.get("CORPUS_PATH", str(_REPO_ROOT / "corpus" / "attack_techniques.json"))
