import prahari.live.threatintel as ti


def _seed(tmp_path):
    (tmp_path / "feodo.txt").write_text("# demo\n52.84.23.17\n45.155.205.0/24  # bad range\n")
    (tmp_path / "providers.json").write_text(
        '[{"cidr":"52.84.0.0/15","provider":"Amazon CloudFront","type":"cdn"}]')
    (tmp_path / "geo.csv").write_text("cidr,country,city\n52.84.0.0/15,US,Seattle\n")


def test_enrich_provider_geo_and_reputation(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(ti.config, "THREATINTEL_DIR", str(tmp_path))
    ti.reset_cache()

    e = ti.enrich("52.84.23.17")
    assert e["provider"] == "Amazon CloudFront" and e["provider_type"] == "cdn"
    assert e["country"] == "US" and e["city"] == "Seattle"
    assert e["reputation"]["listed"] is True and "feodo" in e["reputation"]["sources"]

    # CIDR membership + a clean address
    assert ti.enrich("45.155.205.9")["reputation"]["listed"] is True
    clean = ti.enrich("8.8.8.8")
    assert clean["reputation"]["listed"] is False and clean["provider"] == ""


def test_context_for_string(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(ti.config, "THREATINTEL_DIR", str(tmp_path))
    ti.reset_cache()
    ctx = ti.context_for("52.84.23.17")
    assert "Amazon CloudFront" in ctx and "Seattle" in ctx and "ON BLOCKLIST" in ctx
    assert ti.context_for("8.8.8.8") == ""


def test_missing_dir_is_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(ti.config, "THREATINTEL_DIR", str(tmp_path / "nope"))
    ti.reset_cache()
    assert ti.enrich("1.2.3.4")["reputation"]["listed"] is False
    ti.reset_cache()
