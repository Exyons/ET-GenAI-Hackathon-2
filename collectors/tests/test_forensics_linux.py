import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensics_linux import (
    build_findings, classify_exe, parse_hex_addr, parse_proc_net, rank, score_connection,
)

PROC_NET = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 54321 1 x
   1: 0201A8C0:C7B2 173E3EB2:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99887 1 x
   2: garbage
"""


def test_parse_hex_addr_ipv4_is_little_endian():
    assert parse_hex_addr("0100007F:1F90") == ("127.0.0.1", 8080)
    assert parse_hex_addr("0201A8C0:C7B2") == ("192.168.1.2", 51122)


def test_parse_hex_addr_v4_mapped_v6_reports_as_v4():
    assert parse_hex_addr("0000000000000000FFFF00000100007F:0050") == ("127.0.0.1", 80)


def test_parse_hex_addr_real_ipv6():
    ip, port = parse_hex_addr("0000000000000000000000000100007F:0050")
    assert ":" in ip and port == 80


def test_parse_proc_net_skips_header_and_malformed():
    rows = parse_proc_net(PROC_NET)
    assert len(rows) == 2
    assert rows[0]["state"] == "LISTEN" and rows[0]["inode"] == "54321"
    assert rows[1]["state"] == "ESTABLISHED"
    assert rows[1]["remote_ip"] == "178.62.62.23" and rows[1]["remote_port"] == 443


def test_classify_exe_flags_deleted_and_suspicious_paths():
    assert classify_exe("/tmp/.x/svc (deleted)") == ["deleted_binary", "suspicious_path"]
    assert classify_exe("/dev/shm/payload") == ["suspicious_path"]
    assert classify_exe("/usr/sbin/sshd") == []
    assert classify_exe(None) == ["exe_unreadable"]


def test_score_connection_marks_incident_ioc():
    conn = {"remote_ip": "178.62.62.23", "state": "ESTABLISHED", "flags": []}
    assert "incident_ioc" in score_connection(conn, {"178.62.62.23"})
    assert "incident_ioc" not in score_connection(conn, {"8.8.8.8"})


def test_score_connection_loopback_listener_is_not_flagged():
    listener = {"remote_ip": "0.0.0.0", "local_ip": "127.0.0.1", "state": "LISTEN", "flags": []}
    assert "listening" not in score_connection(listener, set())
    exposed = {"remote_ip": "0.0.0.0", "local_ip": "0.0.0.0", "state": "LISTEN", "flags": []}
    assert "listening" in score_connection(exposed, set())


def test_rank_orders_ioc_above_everything():
    assert rank(["incident_ioc"]) > rank(["deleted_binary"]) > rank(["suspicious_path"]) > rank(["listening"])


def test_findings_attribute_the_owning_process():
    conns = [{
        "pid": "4127", "addr": "178.62.62.23:443", "state": "ESTABLISHED",
        "exe": "/tmp/.x/svc", "user": "osiris", "sha256": "9f2a",
        "flags": ["incident_ioc", "suspicious_path"],
        "parents": [{"pid": "3980", "cmdline": "bash", "exe": "/bin/bash", "user": "osiris"}],
    }]
    out = build_findings(conns, [])
    owner = next(f for f in out if f["title"].startswith("PID 4127 /tmp/.x/svc owns"))
    assert owner["severity"] == "critical"
    assert "osiris" in owner["detail"] and "bash" in owner["detail"]
    assert owner["sha256"] == "9f2a"
    # the world-writable path is reported as its own finding
    assert any("world-writable" in f["title"] for f in out)


def test_findings_flag_deleted_binary_over_suspicious_path():
    conns = [{"pid": "1", "addr": "1.2.3.4:80", "state": "ESTABLISHED", "exe": "/tmp/x (deleted)",
              "flags": ["deleted_binary", "suspicious_path"]}]
    out = build_findings(conns, [])
    assert any("deleted from disk" in f["title"] for f in out)
    assert not any("world-writable" in f["title"] for f in out)


def test_findings_dedup_same_pid_and_address():
    c = {"pid": "7", "addr": "5.5.5.5:443", "state": "ESTABLISHED", "exe": "/x",
         "flags": ["incident_ioc"]}
    assert len(build_findings([c, dict(c)], [])) == 1


def test_findings_report_unattributed_socket_honestly():
    conns = [{"pid": None, "addr": "5.5.5.5:443", "state": "ESTABLISHED", "flags": ["incident_ioc"]}]
    out = build_findings(conns, [])
    assert out[0]["severity"] == "warn"
    assert "owner is unknown" in out[0]["title"] and "root" in out[0]["detail"]


def test_findings_are_severity_ordered():
    conns = [
        {"pid": "1", "addr": "a", "state": "ESTABLISHED", "exe": "/tmp/a", "flags": ["suspicious_path"]},
        {"pid": "2", "addr": "b", "state": "ESTABLISHED", "exe": "/x", "flags": ["incident_ioc"]},
    ]
    out = build_findings(conns, [])
    assert [f["severity"] for f in out] == ["critical", "warn"]
