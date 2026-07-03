from pathlib import Path

from prahari.parsers.cicids import parse_cicids_ml_file, parse_cicids_row

FIX = Path(__file__).parent / "fixtures"


def test_parse_cicids_ml_variant():
    events = list(parse_cicids_ml_file(FIX / "cicids_ml_sample.csv"))
    assert len(events) == 2
    assert all(e.event_type == "network_flow" and e.source == "cicids" for e in events)
    assert events[0].labels == []
    assert events[0].bytes == 6
    assert events[0].duration == 38308.0
    assert events[1].labels == ["attack", "DDoS"]
    assert events[1].bytes == 54000


def test_parse_cicids_row_guards_missing_timestamp():
    # MachineLearningCVE rows have no Timestamp/IP columns
    row = {"Flow Duration": 900000, "Total Length of Fwd Packets": 54000, "Label": "DDoS"}
    ev = parse_cicids_row(row)
    assert ev.bytes == 54000
    assert ev.src_ip is None
    assert ev.timestamp.year == 1970
