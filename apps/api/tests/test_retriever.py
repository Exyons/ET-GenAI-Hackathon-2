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
