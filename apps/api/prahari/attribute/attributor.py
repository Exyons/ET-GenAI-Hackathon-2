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
