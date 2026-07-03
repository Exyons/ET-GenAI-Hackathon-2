from datetime import datetime, timezone

from prahari.detect.features_auth import FEATURE_NAMES, AuthBaseline
from prahari.schema import CanonicalEvent


def _auth(user, src, dst, atype, hour, crit="unknown", labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, hour, 0, 0, tzinfo=timezone.utc),
        event_type="auth",
        source_entity=user,
        src_host=src,
        dst_host=dst,
        auth_type=atype,
        asset_criticality=crit,
        source="lanl",
        labels=labels or [],
        raw="x",
    )


def test_feature_names_length():
    assert len(FEATURE_NAMES) == 5


def test_normal_event_scores_all_low():
    train = [_auth("U100", "C1", "C2", "Kerberos", 15) for _ in range(5)]
    base = AuthBaseline().fit(train)
    f = base.featurize(_auth("U100", "C1", "C2", "Kerberos", 15))
    # seen dest, seen src, common auth type, seen hour, unknown criticality
    assert f == [0.0, 0.0, 0.0, 0.0, 0.0]


def test_novel_event_scores_high():
    train = [_auth("U342", "C1115", "C10", "Kerberos", 15) for _ in range(5)]
    base = AuthBaseline().fit(train)
    # new dest, src is seen (C1115), NTLM never seen, hour 3 novel, critical asset
    f = base.featurize(_auth("U342", "C1115", "C553", "NTLM", 3, crit="critical"))
    is_new_dest, is_new_src, atype_rarity, hour_novelty, dest_crit = f
    assert is_new_dest == 1.0
    assert is_new_src == 0.0
    assert atype_rarity == 1.0  # NTLM never in this user's baseline
    assert hour_novelty == 1.0
    assert dest_crit == 1.0
