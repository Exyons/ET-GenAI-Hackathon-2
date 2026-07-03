"""Real LANL benchmark: behavioural Sentinel vs signature baseline.

Fixture-driven unit test uses a tiny in-format sample. For the real run:

    import gzip
    from prahari.parsers.lanl import load_redteam
    from prahari.data.lanl_slice import slice_auth_lines, redteam_in_window
    with gzip.open("data/auth.txt.gz", "rt") as fh:
        lines = list(slice_auth_lines(fh, 750000, 780000))
    rt = redteam_in_window(load_redteam("data/redteam.txt"), 750000, 780000)
    print(run_lanl_benchmark(lines, rt))
"""
from __future__ import annotations

from prahari.detect.metrics import Metrics, evaluate
from prahari.detect.sentinel import Sentinel
from prahari.detect.signature import SignatureBaseline
from prahari.enrich import enrich
from prahari.parsers.lanl import parse_lanl_line


def run_lanl_benchmark(
    auth_lines: list[str],
    redteam: set[tuple[str, str, str, str]],
    train_frac: float = 0.5,
    quantile: float = 0.99,
) -> dict[str, Metrics]:
    events = [enrich(parse_lanl_line(ln, redteam)) for ln in auth_lines if ln.strip()]
    events.sort(key=lambda e: e.timestamp)

    split = int(len(events) * train_frac)
    train, test = events[:split], events[split:]

    sentinel = Sentinel(random_state=0).fit(train)
    threshold = sentinel.suggest_threshold(train, quantile=quantile)
    sentinel_flags = list(sentinel.anomaly_scores(test) >= threshold)

    signature = SignatureBaseline()
    signature_flags = signature.flag_all(test)

    return {
        "sentinel": evaluate(test, sentinel_flags, positive_label="redteam"),
        "signature": evaluate(test, signature_flags, positive_label="redteam"),
    }
