from datetime import datetime, timezone

from prahari.correlate.incident import Incident
from prahari.live.actions import ActionStore
from prahari.live.playbooks import recommend
from prahari.schema import CanonicalEvent


class _Bus:
    def __init__(self):
        self.events = []

    def publish(self, e):
        self.events.append(e)


def _ev(sec, et, source, **kw):
    return CanonicalEvent(timestamp=datetime(2017, 7, 5, 3, 32, sec, tzinfo=timezone.utc),
                          event_type=et, source=source, raw="x", **kw)


def _incident():
    return Incident(entity="C553", events=[
        _ev(16, "auth", "lanl", source_entity="svc-backup", src_host="C1115", dst_host="C553"),
        _ev(19, "process", "sysmon", source_entity="svc-backup", src_host="C553",
            dest_entity="cmd /c whoami"),
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17", src_internal=False),
    ])


def test_recommend_maps_phases_to_playbooks():
    recs = {(r["playbook"], r["target"]) for r in recommend(_incident())}
    assert ("isolate_host", "C553") in recs          # multi-phase host containment
    assert ("block_ip", "52.84.23.17") in recs       # external C2
    assert ("disable_account", "svc-backup") in recs  # lateral-movement account
    assert ("snapshot", "C553") in recs               # always offered
    assert all(r["reversible"] for r in recommend(_incident()) if r["playbook"] != "kill_process")


def test_block_ip_only_for_public_destinations():
    inc = Incident(entity="C553", events=[
        _ev(16, "auth", "lanl", source_entity="u1", src_host="C1", dst_host="C553"),
        _ev(20, "network_flow", "cicids", src_host="C553", dst_ip="10.0.0.9", src_internal=True),      # internal
        _ev(22, "network_flow", "cicids", src_host="C553", dst_ip="192.168.1.5", src_internal=True),   # private
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17", src_internal=False),  # public
    ])
    targets = {r["target"] for r in recommend(inc) if r["playbook"] == "block_ip"}
    assert targets == {"52.84.23.17"}  # internal / private destinations are never blocked


def test_action_lifecycle_and_audit():
    bus = _Bus()
    store = ActionStore(bus)
    a = store.create("inc-c553", "C553", "isolate_host", "C553", "contain", True)
    assert a.status == "pending_approval" and a.mode == "dry_run"

    # dedup — same open recommendation returns the same action
    assert store.create("inc-c553", "C553", "isolate_host", "C553", "contain", True).id == a.id

    store.approve(a.id, "alice", arm=False)
    assert a.status == "approved" and a.mode == "dry_run" and a.approver == "alice"

    # agent poll hands it over exactly once, marks dispatched
    got = store.pending_for_host("C553")
    assert [x.id for x in got] == [a.id] and a.status == "dispatched"
    assert store.pending_for_host("C553") == []

    store.report(a.id, {"ran": True, "dry_run": True, "command": "nft ...", "error": None})
    assert a.status == "executed"
    assert any(e.get("type") == "action" for e in bus.events)


def test_reject_and_failure_and_stats():
    store = ActionStore(_Bus())
    a = store.create("i", "h", "block_ip", "1.2.3.4", "c2", True)
    store.reject(a.id, "bob")
    assert a.status == "rejected"

    b = store.create("i", "h", "disable_account", "evil", "abuse", True)
    store.approve(b.id, arm=True)
    store.pending_for_host("h")
    store.report(b.id, {"ran": True, "dry_run": False, "error": "permission denied"})
    assert b.status == "failed"

    s = store.stats()
    assert s["total"] == 2 and s["rejected"] == 1 and s["failed"] == 1


def test_revert_creates_paired_undo():
    store = ActionStore(_Bus())
    a = store.create("i", "h", "isolate_host", "h", "contain", True)
    store.approve(a.id, arm=True)
    store.pending_for_host("h")
    store.report(a.id, {"ran": True, "dry_run": False, "error": None})

    r = store.revert(a.id, "alice")
    assert r.undo is True and r.revert_of == a.id and r.status == "approved" and r.mode == "armed"
    assert a.status == "reverted"
    # the undo is dispatched to the agent like any approved action
    assert [x.id for x in store.pending_for_host("h")] == [r.id]
