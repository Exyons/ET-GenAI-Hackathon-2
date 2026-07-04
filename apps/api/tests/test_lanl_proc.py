from pathlib import Path

from prahari.parsers.lanl import parse_lanl_proc_file

FIX = Path(__file__).parent / "fixtures"


def test_proc_parses_start_events_only():
    events = list(parse_lanl_proc_file(FIX / "lanl_proc_sample.txt"))
    # the End record is dropped
    assert len(events) == 2
    assert all(e.event_type == "process" and e.source == "lanl_proc" for e in events)
    e = events[0]
    assert e.src_host == "C1003"
    assert e.source_entity == "C1003$@DOM1"
    assert e.action == "execute"
    assert e.dest_entity == "P47"
