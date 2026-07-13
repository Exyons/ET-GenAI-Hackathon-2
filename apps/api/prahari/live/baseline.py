from __future__ import annotations

import os
import pickle
from pathlib import Path

from prahari.correlate.killchain import killchain_phase
from prahari.schema import CanonicalEvent

BASELINE_FILE = "baseline.pkl"


def _path(state_dir: str | Path) -> Path:
    return Path(state_dir) / BASELINE_FILE


def screen_warmup(
    events: list[CanonicalEvent],
) -> tuple[list[CanonicalEvent], list[CanonicalEvent]]:
    """Deterministic warmup hygiene (no ML → unpoisonable). Suspicious events are
    kept out of the fit and later correlated instead of absorbed as 'normal'."""
    clean: list[CanonicalEvent] = []
    suspicious: list[CanonicalEvent] = []
    for e in events:
        if killchain_phase(e) == "discovery":
            suspicious.append(e)
        elif e.event_type == "auth" and (e.outcome or "").lower() == "failure":
            suspicious.append(e)
        elif e.event_type == "network_flow" and e.src_internal is False:
            suspicious.append(e)
        else:
            clean.append(e)
    return clean, suspicious


# NOTE: pickle here is safe — the baseline file is written by Prahari itself into a
# local, 0o600 state dir and loaded only from that same path (never from untrusted
# input). sklearn IsolationForest models don't round-trip through JSON; pickle/joblib
# is the standard persistence. An attacker able to write STATE_DIR already has code exec.
def save_baseline(state_dir, auth_sentinel, net_sentinel, auth_threshold, net_threshold) -> None:
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    p = _path(state_dir)
    data = {
        "auth_sentinel": auth_sentinel,
        "net_sentinel": net_sentinel,
        "auth_threshold": auth_threshold,
        "net_threshold": net_threshold,
    }
    with open(p, "wb") as f:
        pickle.dump(data, f)
    os.chmod(p, 0o600)


def load_baseline(state_dir) -> dict | None:
    p = _path(state_dir)
    if not p.exists():
        return None
    try:
        with open(p, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None  # corrupt/unreadable → treat as absent


def delete_baseline(state_dir) -> None:
    _path(state_dir).unlink(missing_ok=True)
