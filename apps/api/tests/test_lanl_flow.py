from pathlib import Path

from prahari.parsers.lanl import parse_lanl_flow_file

FIX = Path(__file__).parent / "fixtures"


def test_flow_parses_fields():
    events = list(parse_lanl_flow_file(FIX / "lanl_flow_sample.txt"))
    assert len(events) == 2
    assert all(e.event_type == "network_flow" and e.source == "lanl_flow" for e in events)
    e = events[0]
    assert e.src_host == "C17693"
    assert e.dst_host == "C5074"
    assert e.bytes == 563
    assert e.action == "connect"
    assert events[1].bytes == 4200
    assert events[1].duration == 2.0
