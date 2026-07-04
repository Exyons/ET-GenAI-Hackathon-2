"""Live ATT&CK attribution on the C553 incident. Manual (Ollama): not in CI.

Usage: cd apps/api && PYTHONPATH=. uv run python scripts/run_attribution_demo.py
"""
from __future__ import annotations

import os
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

# Local, air-gapped reasoning model (no cloud auth). Override with PRAHARI_CHAT_MODEL.
CHAT_MODEL = os.environ.get("PRAHARI_CHAT_MODEL", "qwen2.5:7b")


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

    print(f"reasoning with {CHAT_MODEL} (local)...")
    chat_fn = lambda p: ollama_chat(p, model=CHAT_MODEL)  # noqa: E731
    attribution = Attributor(retriever, chat_fn=chat_fn, k=6).attribute(incident)
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
