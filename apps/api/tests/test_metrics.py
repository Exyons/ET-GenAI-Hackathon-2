from datetime import datetime, timezone

from prahari.detect.metrics import Metrics, evaluate
from prahari.schema import CanonicalEvent


def _ev(labels):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, tzinfo=timezone.utc),
        event_type="auth",
        source="lanl",
        labels=labels,
        raw="x",
    )


def test_metrics_math():
    # 2 positives (redteam), 2 negatives
    events = [_ev(["redteam"]), _ev(["redteam"]), _ev([]), _ev([])]
    predicted = [True, False, True, False]  # tp=1, fn=1, fp=1, tn=1
    m = evaluate(events, predicted)
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 1, 1, 1)
    assert m.precision == 0.5
    assert m.recall == 0.5
    assert m.fpr == 0.5
    assert abs(m.f1 - 0.5) < 1e-9


def test_metrics_zero_denominators():
    m = Metrics(tp=0, fp=0, fn=0, tn=5)
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1 == 0.0
    assert m.fpr == 0.0
