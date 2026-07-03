from pathlib import Path

from prahari.parsers.cicids import parse_cicids_file

FIX = Path(__file__).parent / "fixtures"


def test_cicids_parses_flows_and_labels_attacks():
    events = list(parse_cicids_file(FIX / "cicids_sample.csv"))
    assert len(events) == 2
    assert all(e.event_type == "network_flow" and e.source == "cicids" for e in events)

    benign = events[0]
    assert benign.labels == []
    assert benign.src_ip == "192.168.10.5"
    assert benign.dst_ip == "52.84.23.17"
    assert benign.bytes == 220
    assert benign.action == "connect"

    attack = events[1]
    assert attack.labels == ["attack", "DDoS"]
    assert attack.bytes == 54000
