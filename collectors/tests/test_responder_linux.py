import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import responder_linux as r


def _action(playbook, target, mode="dry_run", undo=False):
    return {"id": "act-1", "playbook": playbook, "target": target, "mode": mode, "undo": undo}


def test_build_commands_isolate_keeps_mgmt_port_and_undo():
    cmds = r.build_commands("isolate_host", "web-01", undo=False)
    assert any("policy drop" in c for c in cmds)
    assert any("tcp dport 22 accept" in c for c in cmds)   # don't lock the operator out
    assert r.build_commands("isolate_host", "web-01", undo=True) == ["nft delete table inet prahari"]


def test_build_commands_quote_target():
    # a malicious "target" cannot break out of the command
    cmds = r.build_commands("block_ip", "1.2.3.4; rm -rf /", undo=False)
    assert all("rm -rf" not in c or "'1.2.3.4; rm -rf /'" in c for c in cmds)


def test_disable_account_reversible():
    assert r.build_commands("disable_account", "evil", undo=False) == ["usermod -L evil"]
    assert r.build_commands("disable_account", "evil", undo=True) == ["usermod -U evil"]


def test_dry_run_never_executes():
    out = r.run(_action("isolate_host", "web-01", mode="dry_run"), allow_armed=True)
    assert out["ran"] is False and out["dry_run"] is True
    assert "nft add table inet prahari" in out["command"]


def test_armed_but_agent_not_allowed_stays_dry_run():
    out = r.run(_action("disable_account", "evil", mode="armed"), allow_armed=False)
    assert out["ran"] is False and out["dry_run"] is True
    assert "not armed" in out["note"]


def test_snapshot_is_read_only_and_runs():
    out = r.run(_action("snapshot", "web-01", mode="dry_run"), allow_armed=False)
    # read-only playbook executes even without arming
    assert out["ran"] is True and out["dry_run"] is False
    assert "processes" in out["stdout"].lower()
