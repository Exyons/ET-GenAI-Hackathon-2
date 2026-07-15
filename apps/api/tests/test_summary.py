import time
from datetime import datetime, timezone

import prahari.live.summary as summ
from prahari.correlate.incident import Incident
from prahari.live.pipeline import LivePipeline
from prahari.live.bus import EventBus
from prahari.schema import CanonicalEvent


def _ev(sec, et, source, **kw):
    return CanonicalEvent(timestamp=datetime(2017, 7, 5, 3, 32, sec, tzinfo=timezone.utc),
                          event_type=et, source=source, raw="x", **kw)


def _pipe(tmp_path):
    p = LivePipeline(warmup_seconds=0, window_seconds=300, quantile=0.99,
                     attribute_fn=lambda i: None, bus=EventBus(), state_dir=str(tmp_path))
    p.incidents["inc-c553"] = Incident(entity="C553", events=[
        _ev(16, "auth", "lanl", source_entity="U", src_host="C1", dst_host="C553"),
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17", src_internal=False),
    ])
    return p


def test_build_digest_shape(tmp_path):
    d = summ.build_digest(_pipe(tmp_path))
    assert set(d["phase_counts"]) == {"lateral_movement", "discovery", "execution", "command_and_control"}
    assert d["top_incidents"][0]["entity"] == "C553"
    assert "response" in d and "flag_reasons" in d


def test_summary_caches_and_regenerates(tmp_path, monkeypatch):
    # reset module cache
    summ._cache.update(sig=None, narrative="", generated_at=None, error=None)
    summ._last_attempt = 0.0
    calls = []

    def fake_chat(prompt):
        calls.append(1)
        return "Posture is elevated. One high-confidence incident on C553."

    p = _pipe(tmp_path)
    out = summ.get_summary(p, fake_chat)
    assert out["digest"]["incident_count"] == 1
    # narrative generates in a background thread
    for _ in range(50):
        if summ._cache["narrative"]:
            break
        time.sleep(0.02)
    assert "C553" in summ._cache["narrative"]
    assert len(calls) == 1

    # same state → no regeneration
    summ.get_summary(p, fake_chat)
    time.sleep(0.1)
    assert len(calls) == 1

    # state change → regenerate
    p.incidents["inc-x"] = Incident(entity="X", events=[
        _ev(30, "auth", "lanl", source_entity="U", src_host="A", dst_host="X")])
    summ._last_attempt = 0.0
    summ.get_summary(p, fake_chat)
    for _ in range(50):
        if len(calls) >= 2:
            break
        time.sleep(0.02)
    assert len(calls) == 2


def test_summary_survives_llm_failure(tmp_path):
    summ._cache.update(sig=None, narrative="", generated_at=None, error=None)
    summ._last_attempt = 0.0

    def boom(prompt):
        raise RuntimeError("ollama down")

    out = summ.get_summary(_pipe(tmp_path), boom)
    assert "digest" in out  # digest still returned even when the LLM errors
    for _ in range(50):
        if summ._cache["error"]:
            break
        time.sleep(0.02)
    assert "ollama down" in summ._cache["error"]
