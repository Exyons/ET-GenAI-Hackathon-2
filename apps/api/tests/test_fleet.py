from datetime import datetime, timezone

from prahari.live.fleet import BUCKET_SPAN, Fleet, host_os
from prahari.schema import CanonicalEvent


def _ev(et, source, **kw):
    return CanonicalEvent(timestamp=datetime(2017, 7, 5, 3, 32, 16, tzinfo=timezone.utc),
                          event_type=et, source=source, raw="x", **kw)


def test_host_os_inference():
    assert host_os("linux-auth") == "linux"
    assert host_os("windows-security") == "windows"
    assert host_os("sysmon") == "windows"
    assert host_os("conntrack") == "linux"
    assert host_os("cicids") == "unknown"


def test_observe_tracks_hosts_and_tape():
    clock = [1000.0]
    f = Fleet(clock=lambda: clock[0])
    events = [
        _ev("auth", "linux-auth", source_entity="U100", src_host="WU100", dst_host="C2"),
        _ev("process", "windows-sysmon", source_entity="U100", src_host="WIN7"),
    ]
    tape = f.observe(events, [False, True])

    assert len(tape) == 2 and len(f.tape) == 2
    assert tape[0]["host"] == "C2" and tape[0]["flagged"] is False
    assert tape[1]["host"] == "WIN7" and tape[1]["flagged"] is True

    snap = f.snapshot()
    hosts = {h["host"]: h for h in snap["hosts"]}
    assert hosts["WIN7"]["os"] == "windows" and hosts["C2"]["os"] == "linux"
    assert hosts["WIN7"]["sources"] == ["windows-sysmon"]
    assert snap["by_type"] == {"auth": 1, "process": 1}
    assert snap["rate_epm"] == 2
    assert len(snap["series"]) == BUCKET_SPAN
    assert snap["series"][-1] == {"t": 1000, "auth": 1, "process": 1, "network_flow": 0}


def test_rate_and_last_seen_age_with_clock():
    clock = [1000.0]
    f = Fleet(clock=lambda: clock[0])
    f.observe([_ev("network_flow", "linux-conntrack", src_host="srv1", dst_ip="1.2.3.4")], [False])

    clock[0] = 1090.0  # 90s later: outside the 60s rate window
    snap = f.snapshot()
    (h,) = snap["hosts"]
    assert h["epm"] == 0 and h["last_seen_s"] == 90.0 and h["total"] == 1
    assert snap["rate_epm"] == 0  # bucket aged out of the last-minute window


def test_old_buckets_pruned():
    clock = [1000.0]
    f = Fleet(clock=lambda: clock[0])
    f.observe([_ev("auth", "linux-auth", dst_host="a")], [False])
    clock[0] = 1000.0 + BUCKET_SPAN * 10 + 60
    f.observe([_ev("auth", "linux-auth", dst_host="a")], [False])
    assert len(f._buckets) == 1
