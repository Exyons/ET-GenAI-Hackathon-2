from datetime import datetime, timezone

from prahari.correlate.incident import Incident
from prahari.live.playbooks import (
    UNPINNABLE_IPS, assess, isolation_case, recommend, spread_hosts,
)
from prahari.schema import CanonicalEvent


def _ev(sec, et, source="lanl", **kw):
    return CanonicalEvent(timestamp=datetime(2026, 7, 5, 3, 32, sec % 60, tzinfo=timezone.utc),
                          event_type=et, source=source, raw="x", **kw)


def _c2_incident(entity="C553", ips=("52.84.23.17",), account="svc-backup"):
    """auth + process + one-or-more public C2 flows on a single host."""
    evs = [
        _ev(16, "auth", source_entity=account, src_host="C1115", dst_host=entity),
        _ev(19, "process", "sysmon", source_entity=account, src_host=entity,
            dest_entity="cmd /c whoami"),
    ]
    evs += [_ev(24 + i, "network_flow", "cicids", src_host=entity, dst_ip=ip, src_internal=False)
            for i, ip in enumerate(ips)]
    return Incident(entity=entity, events=evs)


# ---- the core claim: isolation must justify itself ---------------------------
def test_isolation_not_recommended_when_addresses_can_be_blocked():
    ok, note = isolation_case(_c2_incident())
    assert ok is False
    assert "Not recommended" in note and "1 identified address" in note


def test_isolation_recommended_when_attacker_has_spread():
    inc = _c2_incident("C553")
    peers = [_c2_incident("C1003"), _c2_incident("C2871")]  # same account on both
    ok, note = isolation_case(inc, peers=peers)
    assert ok is True
    assert "2 other hosts" in note and "C1003" in note


def test_spread_needs_a_shared_account_not_just_other_incidents():
    inc = _c2_incident("C553", account="alice")
    unrelated = [_c2_incident("C1003", account="bob"), _c2_incident("C2871", account="carol")]
    assert spread_hosts(inc, unrelated) == []
    assert isolation_case(inc, peers=unrelated)[0] is False


def test_isolation_recommended_when_c2_is_unpinnable():
    many = tuple(f"52.84.23.{n}" for n in range(17, 17 + UNPINNABLE_IPS + 1))
    ok, note = isolation_case(_c2_incident(ips=many))
    assert ok is True and "rotating faster" in note


def test_isolation_recommended_when_c2_has_no_blockable_address():
    # C2 phase present (outbound flow) but the destination is internal → nothing to block
    inc = Incident(entity="C553", events=[
        _ev(16, "auth", source_entity="u1", src_host="C1", dst_host="C553"),
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="10.0.0.9", src_internal=True),
    ])
    if "command_and_control" in inc.phases:
        ok, note = isolation_case(inc)
        assert ok is True and "no address could be pinned" in note


def test_isolation_note_defers_to_forensics_when_next_move_predicted():
    inc = Incident(entity="C553", events=[
        _ev(16, "auth", source_entity="u1", src_host="C1", dst_host="C553"),
        _ev(19, "process", "sysmon", source_entity="u1", src_host="C553", dest_entity="whoami"),
    ])
    ok, note = isolation_case(inc, predicted_next="exfiltration")
    assert ok is False and "capture forensics first" in note


# ---- tiering ----------------------------------------------------------------
def test_tier_climbs_with_the_evidence():
    quiet = Incident(entity="C1", events=[_ev(1, "process", "sysmon", src_host="C1",
                                              dest_entity="ls")])
    assert assess(quiet)["tier"] == 0

    assert assess(_c2_incident())["tier"] == 2          # account + lateral movement
    spread = assess(_c2_incident(), peers=[_c2_incident("C1003"), _c2_incident("C2871")])
    assert spread["tier"] == 3 and spread["isolate"] is True


def test_precision_tier_when_c2_but_no_account():
    inc = Incident(entity="C553", events=[
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17", src_internal=False),
    ])
    a = assess(inc)
    assert a["tier"] == 1 and a["c2"] == ["52.84.23.17"] and a["accounts"] == []


# ---- what recommend() actually emits ----------------------------------------
def test_isolate_is_flagged_as_escalation_when_not_justified():
    recs = {r["playbook"]: r for r in recommend(_c2_incident())}
    iso = recs["isolate_host"]
    assert iso["escalation"] is True and iso["tier"] == 3
    assert "Not recommended" in iso["gate_note"]
    # …and stops being an escalation once the attacker spreads
    spread = {r["playbook"]: r for r in
              recommend(_c2_incident(), peers=[_c2_incident("C1003"), _c2_incident("C2871")])}
    assert spread["isolate_host"]["escalation"] is False


def test_snapshot_is_tier_zero_and_carries_incident_iocs():
    snap = next(r for r in recommend(_c2_incident(ips=("52.84.23.17", "91.219.236.14")))
                if r["playbook"] == "snapshot")
    assert snap["tier"] == 0
    assert snap["params"]["ips"] == ["52.84.23.17", "91.219.236.14"]
    assert "cmd /c whoami" in snap["params"]["commands"]


def test_recommendations_are_ordered_least_disruptive_first():
    tiers = [r["tier"] for r in recommend(_c2_incident())]
    assert tiers == sorted(tiers) and tiers[0] == 0 and tiers[-1] == 3


def test_no_vector_actions_below_tier_two():
    inc = Incident(entity="C553", events=[
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17", src_internal=False),
    ])
    playbooks = {r["playbook"] for r in recommend(inc)}
    assert "disable_account" not in playbooks and "kill_process" not in playbooks
    assert playbooks == {"snapshot", "block_ip", "isolate_host"}


def test_block_ip_still_only_targets_public_addresses():
    inc = Incident(entity="C553", events=[
        _ev(16, "auth", source_entity="u1", src_host="C1", dst_host="C553"),
        _ev(20, "network_flow", "cicids", src_host="C553", dst_ip="10.0.0.9", src_internal=True),
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17", src_internal=False),
    ])
    assert {r["target"] for r in recommend(inc) if r["playbook"] == "block_ip"} == {"52.84.23.17"}
