import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sources_windows import map_process, map_security_auth, map_sysmon_network

TS = "2026-07-08T12:00:00+00:00"


def _xml(event_id: int, data: dict[str, str]) -> str:
    fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System><EventID>{event_id}</EventID></System>"
            f"<EventData>{fields}</EventData></Event>")


def test_map_security_auth_success():
    xml = _xml(4624, {"TargetUserName": "alice", "IpAddress": "203.0.113.9",
                      "AuthenticationPackageName": "NTLM", "LogonType": "3"})
    d = map_security_auth(xml, TS, "WIN-DC1")
    assert d["event_type"] == "auth" and d["source"] == "windows-security"
    assert d["source_entity"] == "alice" and d["src_ip"] == "203.0.113.9"
    assert d["outcome"] == "success" and d["auth_type"] == "NTLM"
    assert d["src_host"] == "WIN-DC1" and d["dst_host"] == "WIN-DC1"


def test_map_security_auth_failure():
    xml = _xml(4625, {"TargetUserName": "administrator", "IpAddress": "10.0.0.5",
                      "AuthenticationPackageName": "NTLM"})
    d = map_security_auth(xml, TS, "WIN-DC1")
    assert d["outcome"] == "failure" and d["source_entity"] == "administrator"


def test_map_security_auth_skips_machine_and_service_accounts():
    assert map_security_auth(_xml(4624, {"TargetUserName": "WIN-DC1$"}), TS, "WIN-DC1") is None
    assert map_security_auth(_xml(4624, {"TargetUserName": "SYSTEM"}), TS, "WIN-DC1") is None
    assert map_security_auth(_xml(4672, {"TargetUserName": "alice"}), TS, "WIN-DC1") is None


def test_map_process_sysmon():
    xml = _xml(1, {"CommandLine": "cmd /c whoami", "Image": "C:\\Windows\\System32\\cmd.exe",
                   "User": "CORP\\alice"})
    d = map_process(xml, TS, "WIN-WS7")
    assert d["event_type"] == "process" and d["source"] == "windows-sysmon"
    assert d["dest_entity"] == "cmd /c whoami" and d["source_entity"] == "CORP\\alice"
    assert d["src_host"] == "WIN-WS7"


def test_map_process_4688_fallback():
    xml = _xml(4688, {"NewProcessName": "C:\\Windows\\System32\\net.exe",
                      "SubjectUserName": "bob"})
    d = map_process(xml, TS, "WIN-WS7")
    assert d["source"] == "windows-security"
    assert d["dest_entity"] == "C:\\Windows\\System32\\net.exe"


def test_map_sysmon_network():
    xml = _xml(3, {"SourceIp": "192.168.1.7", "DestinationIp": "52.84.23.17",
                   "Image": "C:\\evil.exe"})
    d = map_sysmon_network(xml, TS, "WIN-WS7")
    assert d["event_type"] == "network_flow" and d["source"] == "windows-sysmon"
    assert d["dst_ip"] == "52.84.23.17" and d["src_internal"] is True


def test_sysmon_network_skips_loopback():
    for dst in ("127.0.0.1", "::1"):
        assert map_sysmon_network(_xml(3, {"DestinationIp": dst}), TS) is None


def test_mappers_ignore_other_events():
    assert map_process(_xml(5, {"CommandLine": "x"}), TS) is None
    assert map_sysmon_network(_xml(1, {"DestinationIp": "1.2.3.4"}), TS) is None
