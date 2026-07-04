from prahari.api.demo import ATTRIBUTIONS, demo_incidents, incident_id


def test_demo_has_c553_high_confidence_incident():
    incidents = demo_incidents()
    ids = {incident_id(i) for i in incidents}
    assert "inc-c553" in ids

    c553 = next(i for i in incidents if incident_id(i) == "inc-c553")
    assert c553.high_confidence is True
    assert c553.is_true_positive is True
    assert len(c553.sources) == 3
    assert len(c553.phases) == 3


def test_c553_has_recorded_attribution():
    attr = ATTRIBUTIONS["inc-c553"]
    assert "T1021.006" in attr["technique_ids"]
    assert attr["predicted_next"] == "exfiltration"
    assert attr["grounded"] is True
