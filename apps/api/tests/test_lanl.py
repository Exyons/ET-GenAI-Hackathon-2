from pathlib import Path

from prahari.parsers.lanl import load_redteam, parse_lanl_file

FIX = Path(__file__).parent / "fixtures"


def test_lanl_parses_and_labels_redteam():
    redteam = load_redteam(FIX / "lanl_redteam_sample.txt")
    events = list(parse_lanl_file(FIX / "lanl_auth_sample.txt", FIX / "lanl_redteam_sample.txt"))

    assert len(events) == 3
    assert all(e.event_type == "auth" and e.source == "lanl" for e in events)

    flagged = [e for e in events if "redteam" in e.labels]
    assert len(flagged) == 1
    e = flagged[0]
    assert e.source_entity == "U342@DOM1"
    assert e.src_host == "C1115"
    assert e.dst_host == "C553"
    assert e.action == "login"
    assert e.outcome == "success"
    assert e.raw.startswith("151036,U342@DOM1")
    # ("151036","U342@DOM1","C1115","C553") is in the redteam set
    assert ("151036", "U342@DOM1", "C1115", "C553") in redteam
    assert e.auth_type == "NTLM"
