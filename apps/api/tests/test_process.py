from pathlib import Path

from prahari.parsers.process import parse_sysmon_file

FIX = Path(__file__).parent / "fixtures"


def test_sysmon_parses_process_events():
    events = list(parse_sysmon_file(FIX / "sysmon_sample.jsonl"))
    assert len(events) == 2
    assert all(e.event_type == "process" and e.source == "sysmon" for e in events)

    redteam = [e for e in events if "redteam" in e.labels]
    assert len(redteam) == 1
    e = redteam[0]
    assert e.source_entity == "U342@DOM1"
    assert e.src_host == "C553"
    assert e.action == "execute"
    assert "whoami" in e.dest_entity
    assert e.timestamp.year == 2017
