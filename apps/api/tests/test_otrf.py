from pathlib import Path

from prahari.parsers.process import parse_otrf_lines

FIX = Path(__file__).parent / "fixtures"


def test_otrf_filters_to_process_create_and_maps_fields():
    lines = (FIX / "otrf_sample.jsonl").read_text().splitlines()
    events = list(parse_otrf_lines(lines, labels=["attack", "T1059"]))

    # only the two EventID==1 records survive (the EventID 3 network event is dropped)
    assert len(events) == 2
    e = events[0]
    assert e.event_type == "process"
    assert e.src_host == "WORKSTATION5"
    assert e.source_entity == "WORKSTATION5\\APT-Simulator"
    assert "ping" in e.dest_entity
    assert e.labels == ["attack", "T1059"]
    assert e.timestamp.year == 2021
    assert "whoami" in events[1].dest_entity
