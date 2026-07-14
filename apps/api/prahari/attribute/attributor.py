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


def _event_detail(e) -> str:
    # factual, field-derived phrasing so retrieval/reasoning see the real signal
    if e.event_type == "auth":
        mech = f" ({e.auth_type})" if e.auth_type else ""
        return f"remote login{mech} to {e.dst_host or ''}".strip()
    if e.event_type == "process":
        return f"executed {e.dest_entity or ''}".strip()
    if e.event_type == "network_flow":
        dest = e.dst_ip or e.dst_host or ""
        scope = "external " if e.src_internal is False else ""
        return f"outbound {scope}connection to {dest}".strip()
    return e.dest_entity or e.dst_host or e.dst_ip or ""


def summarize_incident(incident: Incident) -> str:
    lines = [f"Incident on entity {incident.entity}. "
             f"Phases: {', '.join(sorted(incident.phases))}. Timeline:"]
    for e in incident.timeline():
        phase = killchain_phase(e)
        lines.append(f"- {e.event_type} {phase}: {e.source_entity or ''} {_event_detail(e)}")
    return "\n".join(lines)


_PROMPT = """You are a SOC analyst mapping an intrusion to MITRE ATT&CK.
For EACH step in the incident timeline, choose the single candidate technique ID that
best matches that step's action. Make sure lateral movement (a remote login), the
executed command, and any outbound command-and-control traffic are each mapped when
present. Then explain briefly.

Respond ONLY as JSON: {{"technique_ids": ["T####", ...], "explanation": "..."}}
Use ONLY technique IDs from the candidate list below.

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

    def _event_queries(self, incident: Incident) -> list[str]:
        # one query per event so every kill-chain phase gets retrieval coverage,
        # instead of a single incident query that the busiest phase dominates.
        queries = [summarize_incident(incident)]
        for e in incident.timeline():
            queries.append(f"{e.event_type} {killchain_phase(e)}: {_event_detail(e)}")
        return queries

    def attribute(self, incident: Incident) -> Attribution:
        summary = summarize_incident(incident)
        # union top-k retrievals across per-event queries (keep best score per id)
        best: dict[str, tuple] = {}
        for q in self._event_queries(incident):
            for doc, score in self.retriever.retrieve(q, k=self.k):
                if doc.id not in best or score > best[doc.id][1]:
                    best[doc.id] = (doc, score)
        hits = sorted(best.values(), key=lambda x: x[1], reverse=True)
        retrieved_ids = [doc.id for doc, _ in hits]
        candidates = "\n".join(f"{doc.id} {doc.name}: {doc.description}" for doc, _ in hits)
        raw = self.chat_fn(_PROMPT.format(summary=summary, candidates=candidates))

        parsed = _parse_json(raw)
        allowed = set(retrieved_ids)
        # the prompt maps one technique per timeline step, so the model repeats an
        # ID when steps share a technique — dedupe, preserving first-seen order
        ids = list(dict.fromkeys(
            tid for tid in parsed.get("technique_ids", []) if tid in allowed))
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
