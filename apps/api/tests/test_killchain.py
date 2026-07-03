from datetime import datetime, timezone

from prahari.correlate.killchain import actor_of, killchain_phase, target_of
from prahari.schema import CanonicalEvent


def _ev(**kw):
    base = dict(
        timestamp=datetime(2017, 7, 5, 15, tzinfo=timezone.utc),
        source="lanl", raw="x",
    )
    base.update(kw)
    return CanonicalEvent(**base)


def test_phase_for_auth():
    e = _ev(event_type="auth", source_entity="U1", src_host="C1", dst_host="C553")
    assert killchain_phase(e) == "lateral_movement"
    assert actor_of(e) == "U1"
    assert target_of(e) == "C553"


def test_phase_for_process_discovery_vs_execution():
    d = _ev(event_type="process", source_entity="U1", src_host="C553", dest_entity="cmd /c whoami")
    x = _ev(event_type="process", source_entity="U1", src_host="C553", dest_entity="notepad.exe")
    assert killchain_phase(d) == "discovery"
    assert killchain_phase(x) == "execution"
    assert target_of(d) == "C553"


def test_phase_for_network():
    n = _ev(event_type="network_flow", src_host="C553", dst_ip="52.84.23.17")
    assert killchain_phase(n) == "command_and_control"
    assert target_of(n) == "C553"
