from __future__ import annotations

from dataclasses import dataclass

from prahari.schema import CanonicalEvent


@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0


def evaluate(
    events: list[CanonicalEvent],
    predicted: list[bool],
    positive_label: str = "redteam",
) -> Metrics:
    tp = fp = fn = tn = 0
    for event, flag in zip(events, predicted, strict=True):
        is_positive = positive_label in event.labels
        if flag and is_positive:
            tp += 1
        elif flag and not is_positive:
            fp += 1
        elif not flag and is_positive:
            fn += 1
        else:
            tn += 1
    return Metrics(tp=tp, fp=fp, fn=fn, tn=tn)
