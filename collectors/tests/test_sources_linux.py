import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sources_linux import is_internal, map_audit_execve, map_auth, map_conntrack

TS = "2026-07-08T12:00:00+00:00"


def test_map_auth_accepted():
    d = map_auth("Accepted publickey for alice from 203.0.113.9 port 51000 ssh2", TS, "vm1")
    assert d["event_type"] == "auth" and d["source"] == "linux-auth"
    assert d["source_entity"] == "alice" and d["src_ip"] == "203.0.113.9"
    assert d["outcome"] == "success" and d["auth_type"] == "publickey"
    assert d["src_host"] == "vm1" and d["dst_host"] == "vm1"


def test_map_auth_failed_invalid_user():
    d = map_auth("Failed password for invalid user root from 10.0.0.5 port 2222 ssh2", TS, "vm1")
    assert d["outcome"] == "failure" and d["source_entity"] == "root"


def test_map_auth_ignores_noise():
    assert map_auth("Server listening on 0.0.0.0 port 22.", TS, "vm1") is None


def test_map_audit_execve():
    line = ('type=SYSCALL msg=audit(1750000000.0:42): arch=c000003e syscall=execve success=yes '
            'AUID="alice" uid=1000 comm="whoami" exe="/usr/bin/whoami"')
    d = map_audit_execve(line, TS, "vm1")
    assert d["event_type"] == "process" and d["source"] == "linux-audit"
    assert d["src_host"] == "vm1" and d["source_entity"] == "alice"
    assert d["dest_entity"] == "/usr/bin/whoami"


def test_map_conntrack_new_outbound():
    line = "[NEW] tcp 6 120 SYN_SENT src=10.0.0.5 dst=52.84.23.17 sport=54321 dport=443"
    d = map_conntrack(line, TS, "vm1")
    assert d["event_type"] == "network_flow" and d["source"] == "linux-conntrack"
    assert d["dst_ip"] == "52.84.23.17" and d["src_host"] == "vm1"
    assert d["src_internal"] is True


def test_is_internal():
    assert is_internal("10.0.0.9") and is_internal("192.168.1.1") and is_internal("172.16.0.1")
    assert not is_internal("52.84.23.17")
