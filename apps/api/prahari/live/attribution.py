from __future__ import annotations

from collections.abc import Callable

from prahari import config
from prahari.api.models import AttributionView, TechniqueView
from prahari.attribute.attributor import Attributor
from prahari.attribute.corpus import load_corpus, short_description
from prahari.attribute.ollama import ollama_chat, ollama_embed
from prahari.attribute.predictor import ATTACK_TACTIC_PRIOR, TacticPredictor
from prahari.attribute.retriever import Retriever
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import killchain_phase

# kill-chain phase → ATT&CK tactic (mirrors scripts/run_attribution_demo.py)
_PHASE_TACTIC = {
    "command_and_control": "command-and-control",
    "discovery": "discovery",
    "lateral_movement": "lateral-movement",
    "execution": "execution",
}


def build_attribute_fn(
    corpus_path: str,
    chat_fn: Callable[[str], str] | None = None,
    embed_fn: Callable[[list[str]], object] | None = None,
    k: int = 6,
) -> Callable[[Incident], AttributionView]:
    """Assemble the live attribution function. Embeds the corpus once; each call
    retrieves + reasons + predicts. Fully injectable so tests skip Ollama."""
    chat_fn = chat_fn or (lambda p: ollama_chat(p, model=config.CHAT_MODEL, host=config.OLLAMA_HOST))
    embed_fn = embed_fn or (lambda texts: ollama_embed(texts, model=config.EMBED_MODEL,
                                                       host=config.OLLAMA_HOST))

    corpus = load_corpus(corpus_path)
    doc_by_id = {d.id: d for d in corpus}
    retriever = Retriever(embed_fn=embed_fn).fit(corpus)
    predictor = TacticPredictor().fit(ATTACK_TACTIC_PRIOR)

    def attribute(incident: Incident) -> AttributionView:
        attr = Attributor(retriever, chat_fn=chat_fn, k=k).attribute(incident)
        techniques = []
        for tid in attr.technique_ids:
            doc = doc_by_id.get(tid)
            if doc is not None:
                tactic = doc.tactics[0] if doc.tactics else ""
                techniques.append(TechniqueView(id=tid, name=doc.name, tactic=tactic,
                                                description=short_description(doc.description)))
        last_phase = killchain_phase(incident.timeline()[-1])
        tactic = _PHASE_TACTIC.get(last_phase, last_phase)
        nxt = predictor.predict_next(tactic, k=1)
        predicted_next = nxt[0][0] if nxt else ""
        return AttributionView(
            technique_ids=attr.technique_ids,
            techniques=techniques,
            explanation=attr.explanation,
            grounded=bool(attr.technique_ids),
            predicted_next=predicted_next,
        )

    return attribute
