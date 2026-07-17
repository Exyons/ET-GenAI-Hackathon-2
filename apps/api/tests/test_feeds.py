import prahari.live.feeds as feeds
import prahari.live.threatintel as ti


def test_refresh_writes_feed_and_enriches(tmp_path, monkeypatch):
    monkeypatch.setattr(ti.config, "THREATINTEL_DIR", str(tmp_path))
    monkeypatch.setattr(feeds.config, "THREATINTEL_DIR", str(tmp_path))
    monkeypatch.setattr(feeds.config, "THREATINTEL_FEEDS", ["http://feed.test/level1.netset"])
    ti.reset_cache()

    body = "# aggregated\n203.0.113.0/24\n198.51.100.7\n"
    st = feeds.refresh(fetch=lambda url, timeout=20.0: body)

    assert st["feeds"]["http://feed.test/level1.netset"]["ok"] is True
    assert st["feeds"]["http://feed.test/level1.netset"]["entries"] == 2
    assert (tmp_path / "feed-level1.netset.txt").is_file()
    # the fetched range now enriches as listed
    assert ti.enrich("203.0.113.9")["reputation"]["listed"] is True


def test_refresh_records_unreachable_feed(tmp_path, monkeypatch):
    monkeypatch.setattr(ti.config, "THREATINTEL_DIR", str(tmp_path))
    monkeypatch.setattr(feeds.config, "THREATINTEL_DIR", str(tmp_path))
    monkeypatch.setattr(feeds.config, "THREATINTEL_FEEDS", ["http://down.test/list"])
    ti.reset_cache()

    def boom(url, timeout=20.0):
        raise OSError("connection refused")

    st = feeds.refresh(fetch=boom)
    assert st["feeds"]["http://down.test/list"]["ok"] is False
    assert "OSError" in st["feeds"]["http://down.test/list"]["error"]


def test_add_operator_entry_persists_and_dedups(tmp_path, monkeypatch):
    monkeypatch.setattr(ti.config, "THREATINTEL_DIR", str(tmp_path))
    ti.reset_cache()

    ti.add_blocklist_entry("66.77.88.0/24", note="analyst flagged")
    assert ti.enrich("66.77.88.5")["reputation"]["listed"] is True
    assert "operator" in ti.enrich("66.77.88.5")["reputation"]["sources"]

    # idempotent — same CIDR is not written twice
    ti.add_blocklist_entry("66.77.88.0/24")
    lines = [ln for ln in (tmp_path / "operator.txt").read_text().splitlines() if ln.strip()]
    assert len(lines) == 1

    import pytest
    with pytest.raises(ValueError):
        ti.add_blocklist_entry("not-an-ip")
    ti.reset_cache()
