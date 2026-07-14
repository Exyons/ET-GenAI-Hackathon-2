"""The three anti-noise rules: warmup-learned process commands are never flagged,
flagged processes don't cascade into flagging more processes, and a repeating
discovery command is reported once per window."""
import asyncio
from datetime import datetime, timedelta, timezone

from prahari.api.models import AttributionView
from prahari.live.bus import EventBus
from prahari.live.pipeline import LivePipeline, norm_cmd
from prahari.schema import CanonicalEvent

T0 = datetime(2017, 7, 5, 15, 0, 0, tzinfo=timezone.utc)


def _ev(sec, et, source, **kw):
    return CanonicalEvent(timestamp=T0 + timedelta(seconds=sec),
                          event_type=et, source=source, raw="x", **kw)


def _warmup():
    events = [_ev(i, "auth", "linux-auth", source_entity="deploy", src_host="web-01",
                  dst_host="web-01", auth_type="publickey", outcome="success")
              for i in range(12)]
    # a "system service" command that runs all the time on this fleet
    events += [_ev(i, "process", "linux-proc", source_entity="root", src_host="web-01",
                   dest_entity="/usr/lib/systemd/systemd-hostnamed") for i in range(4)]
    return events


def _pipe(tmp_path):
    return LivePipeline(warmup_seconds=0, window_seconds=300, quantile=0.99,
                        attribute_fn=lambda i: AttributionView(
                            technique_ids=[], techniques=[], explanation="",
                            grounded=False, predicted_next=""),
                        bus=EventBus(), state_dir=str(tmp_path))


def _fitted(tmp_path):
    p = _pipe(tmp_path)
    asyncio.run(p.ingest(_warmup()))
    asyncio.run(p.ingest([_ev(60, "auth", "linux-auth", source_entity="deploy",
                              src_host="web-01", dst_host="web-01",
                              auth_type="publickey", outcome="success")]))
    assert p.mode == "monitoring" and p.process_baseline
    return p


def test_norm_cmd():
    assert norm_cmd("  /usr/bin/FOO   --bar  ") == "/usr/bin/foo --bar"


def test_warmup_process_commands_not_flagged(tmp_path):
    p = _fitted(tmp_path)
    known = _ev(100, "process", "linux-proc", source_entity="root", src_host="web-01",
                dest_entity="/usr/lib/systemd/systemd-hostnamed")
    unknown = _ev(101, "process", "linux-proc", source_entity="root", src_host="web-01",
                  dest_entity="sh -c whoami")
    assert p._flag_reason(known) is None          # learned normal — silent
    assert p._flag_reason(unknown) == "discovery"  # never seen + recon keyword


def test_flagged_process_does_not_cascade(tmp_path):
    p = _fitted(tmp_path)
    asyncio.run(p.ingest([_ev(100, "process", "linux-proc", source_entity="root",
                              src_host="web-01", dest_entity="sh -c whoami")]))
    assert len(p.recent) == 1  # the discovery flag itself
    # ordinary processes on the same host stay silent — no process→process cascade
    asyncio.run(p.ingest([_ev(101 + i, "process", "linux-proc", source_entity="root",
                              src_host="web-01", dest_entity=f"/usr/bin/task-{i}")
                          for i in range(5)]))
    assert len(p.recent) == 1
    # …but an auth anomaly on the host makes the next process corroborate
    p.recent.append(_ev(102, "auth", "linux-auth", source_entity="x", src_host="a",
                        dst_host="web-01", auth_type="NTLM", outcome="success"))
    follow = _ev(103, "process", "linux-proc", source_entity="root", src_host="web-01",
                 dest_entity="/usr/bin/task-x")
    assert p._flag_reason(follow) == "process_corroborated"


def test_discovery_dedup_once_per_window(tmp_path):
    p = _fitted(tmp_path)
    spam = [_ev(100 + i, "process", "linux-proc", source_entity="root", src_host="web-01",
                dest_entity="sh -c whoami") for i in range(6)]
    asyncio.run(p.ingest(spam))
    assert len(p.recent) == 1  # reported once, not six times
    assert p.stats["discovery"] == 1
    # a full window after the LAST sighting, the same command is notable again
    # (continuous repeats keep refreshing the suppression — noise stays quiet)
    late = _ev(105 + 301, "process", "linux-proc", source_entity="root", src_host="web-01",
               dest_entity="sh -c whoami")
    assert p._flag_reason(late) == "discovery"


def test_attribution_error_is_surfaced(tmp_path):
    p = _fitted(tmp_path)

    def boom(_):
        raise RuntimeError("ollama 404: model 'embeddinggemma' not found, try pulling it first")
    p.attribute_fn = boom
    # NTLM anomaly + recon command on web-01 → high-confidence → attribution attempt
    asyncio.run(p.ingest([
        _ev(100, "auth", "linux-auth", source_entity="evil", src_host="kali",
            dst_host="web-01", auth_type="NTLM", outcome="failure"),
        _ev(101, "process", "linux-proc", source_entity="evil", src_host="web-01",
            dest_entity="sh -c whoami"),
    ]))
    info = p.status()["pipeline"]
    assert info["attribution_error"] is not None
    assert "embeddinggemma" in info["attribution_error"]
    assert info["models"]["chat"] and info["models"]["embed"]
