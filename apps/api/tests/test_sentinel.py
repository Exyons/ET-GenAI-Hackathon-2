from datetime import datetime, timezone

from prahari.detect.sentinel import Sentinel
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


def _normal_traffic(n=30):
    # benign but varied: multiple users, known hosts/hours, mostly Kerberos with
    # the occasional benign NTLM, mixed low/medium asset criticality. This gives
    # IsolationForest a real distribution to learn (unlike identical rows).
    users = ["U100", "U200", "U300"]
    dests = {"U100": ["C1", "C2"], "U200": ["C3", "C4"], "U300": ["C5", "C6"]}
    hours = [9, 13, 15, 17]
    events = []
    for i in range(n):
        u = users[i % 3]
        dst = dests[u][i % 2]
        atype = "NTLM" if i % 7 == 0 else "Kerberos"
        crit = "medium" if i % 2 == 0 else "low"
        events.append(_auth(u, f"W{u}", dst, atype, hours[i % 4], crit=crit))
    return events


def _redteam():
    # low-and-slow lateral movement: known user/src, but new critical dest,
    # rare auth mechanism, dead-of-night hour.
    return _auth("U100", "WU100", "C553", "NTLM", 3, crit="critical", labels=["redteam"])


def test_redteam_event_is_most_anomalous():
    train = _normal_traffic()
    sentinel = Sentinel(random_state=0).fit(train)

    population = train + [_redteam()]
    scores = [sentinel.anomaly_score(e) for e in population]

    # the red-team event has the single highest anomaly score
    assert scores.index(max(scores)) == len(population) - 1


def test_flag_anomalies_catches_redteam_above_threshold():
    train = _normal_traffic()
    sentinel = Sentinel(random_state=0).fit(train)
    threshold = sentinel.suggest_threshold(train, quantile=0.95)

    flags = sentinel.flag_anomalies(train + [_redteam()], threshold)

    assert flags[-1] is True  # red-team flagged
    assert sum(flags[:-1]) <= 3  # very few false positives on benign
