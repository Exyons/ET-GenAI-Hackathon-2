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
