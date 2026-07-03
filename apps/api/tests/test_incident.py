from datetime import datetime, timezone

from prahari.correlate.incident import Incident
from prahari.schema import CanonicalEvent


def _ev(sec, event_type, source, **kw):
    base = dict(
        timestamp=datetime(2017, 7, 5, 15, 32, sec, tzinfo=timezone.utc),
        event_type=event_type, source=source, raw="x",
    )
    base.update(kw)
    return CanonicalEvent(**base)


def test_single_source_incident_is_low_compound():
    inc = Incident(entity="U1", events=[
        _ev(0, "auth", "lanl", source_entity="U1", dst_host="C2"),
    ])
    assert inc.high_confidence is False
    assert inc.compound_score < 0.5
    assert inc.sources == {"lanl"}
    assert inc.phases == {"lateral_movement"}


def test_multi_source_multi_phase_is_high_confidence():
    inc = Incident(entity="C553", events=[
        _ev(16, "auth", "lanl", source_entity="U342", dst_host="C553",
            asset_criticality="critical", labels=["redteam"]),
        _ev(19, "process", "otrf", source_entity="U342", src_host="C553",
            dest_entity="cmd /c whoami"),
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17"),
    ])
    assert inc.sources == {"lanl", "otrf", "cicids"}
    assert inc.phases == {"lateral_movement", "discovery", "command_and_control"}
    assert inc.high_confidence is True
    assert inc.is_true_positive is True
    assert inc.compound_score > 0.8
    assert [e.event_type for e in inc.timeline()] == ["auth", "process", "network_flow"]
