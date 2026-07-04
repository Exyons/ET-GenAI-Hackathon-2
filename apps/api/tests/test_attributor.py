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
