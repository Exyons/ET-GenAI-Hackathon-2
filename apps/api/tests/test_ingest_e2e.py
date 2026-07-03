from pathlib import Path

from prahari.ingest import load_all

FIX = Path(__file__).parent / "fixtures"


def test_load_all_produces_ordered_enriched_labeled_stream():
    events = load_all(
        lanl_auth=FIX / "lanl_auth_sample.txt",
        lanl_redteam=FIX / "lanl_redteam_sample.txt",
        cicids=FIX / "cicids_sample.csv",
        sysmon=FIX / "sysmon_sample.jsonl",
    )
    # 3 LANL + 2 CICIDS + 2 sysmon
    assert len(events) == 7

    # ordered by timestamp
    ts = [e.timestamp for e in events]
    assert ts == sorted(ts)

    # red-team labels survived ingestion (LANL auth + sysmon process)
    redteam = [e for e in events if "redteam" in e.labels]
    assert len(redteam) == 2
    assert {e.event_type for e in redteam} == {"auth", "process"}

    # enrichment ran: the C553 critical asset is tagged
    c553 = [e for e in events if e.dst_host == "C553" or e.src_host == "C553"]
    assert any(e.asset_criticality == "critical" for e in c553)


def test_load_all_skips_missing_sources():
    events = load_all(
        lanl_auth=FIX / "lanl_auth_sample.txt",
        lanl_redteam=FIX / "lanl_redteam_sample.txt",
        cicids=None,
        sysmon=None,
    )
    assert len(events) == 3
    assert all(e.source == "lanl" for e in events)
