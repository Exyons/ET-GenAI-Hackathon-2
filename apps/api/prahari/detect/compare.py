from __future__ import annotations

from prahari.detect.metrics import Metrics, evaluate
from prahari.detect.sentinel import Sentinel
from prahari.detect.signature import SignatureBaseline
from prahari.schema import CanonicalEvent


def compare_detectors(
    train: list[CanonicalEvent],
    test: list[CanonicalEvent],
    bad_ips: set[str] | None = None,
    quantile: float = 0.95,
) -> dict[str, Metrics]:
    sentinel = Sentinel(random_state=0).fit(train)
    threshold = sentinel.suggest_threshold(train, quantile=quantile)
    sentinel_flags = sentinel.flag_anomalies(test, threshold)

    signature = SignatureBaseline(bad_ips=bad_ips)
    signature_flags = signature.flag_all(test)

    return {
        "sentinel": evaluate(test, sentinel_flags, positive_label="redteam"),
        "signature": evaluate(test, signature_flags, positive_label="redteam"),
    }
