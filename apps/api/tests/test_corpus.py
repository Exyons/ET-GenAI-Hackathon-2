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
