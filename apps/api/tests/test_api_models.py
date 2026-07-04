from datetime import datetime, timezone

from prahari.api.models import (
    AttributionView, EventView, IncidentSummary, MetricsView, TechniqueView,
)


def test_models_construct_and_serialize():
    ev = EventView(timestamp=datetime(2017, 7, 5, 15, 32, 16, tzinfo=timezone.utc),
                   event_type="auth", phase="lateral_movement", source="lanl",
                   actor="U342@DOM1", detail="remote login (NTLM) to C553")
    assert ev.model_dump()["phase"] == "lateral_movement"

    attr = AttributionView(technique_ids=["T1021.006"],
                           techniques=[TechniqueView(id="T1021.006", name="Remote Services", tactic="lateral-movement")],
                           explanation="lateral movement", grounded=True, predicted_next="exfiltration")
    assert attr.grounded is True

    summ = IncidentSummary(id="inc-c553", entity="C553", compound_score=0.94, high_confidence=True,
                           is_true_positive=True, phase_count=3, source_count=3, event_count=3,
                           start=datetime(2017, 7, 5, 15, 32, 16, tzinfo=timezone.utc))
    assert summ.high_confidence is True

    m = MetricsView(behavioural_recall=0.794, signature_recall=0.0, mttd_seconds=41,
                    attack_techniques=697, false_positive_rate=0.075)
    assert m.behavioural_recall == 0.794
