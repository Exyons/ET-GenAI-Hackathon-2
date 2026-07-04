from prahari.api.demo import demo_incidents, incident_id
from prahari.api.serialize import to_detail, to_summary


def _c553():
    return next(i for i in demo_incidents() if incident_id(i) == "inc-c553")


def test_summary_fields():
    s = to_summary(_c553())
    assert s.id == "inc-c553"
    assert s.entity == "C553"
    assert s.high_confidence is True
    assert s.source_count == 3
    assert s.phase_count == 3
    assert s.compound_score > 0.8


def test_detail_timeline_and_attribution():
    d = to_detail(_c553())
    assert [e.event_type for e in d.timeline] == ["auth", "process", "network_flow"]
    assert d.timeline[0].phase == "lateral_movement"
    assert "C553" in d.timeline[0].detail
    assert "T1021.006" in d.attribution.technique_ids
    assert d.attribution.predicted_next == "exfiltration"
