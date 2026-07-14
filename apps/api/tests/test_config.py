import os

from prahari.config import load_dotenv


def test_load_dotenv_parses_and_respects_real_env(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        "# comment line\n"
        "PRAHARI_TEST_TOKEN=secret-123       # inline comment\n"
        "PRAHARI_TEST_QUOTED='qwen2.5:7b'\n"
        "PRAHARI_TEST_EXISTING=from-file\n"
        "not a kv line\n"
    )
    monkeypatch.setenv("PRAHARI_TEST_EXISTING", "from-env")
    monkeypatch.delenv("PRAHARI_TEST_TOKEN", raising=False)
    monkeypatch.delenv("PRAHARI_TEST_QUOTED", raising=False)

    load_dotenv(env)
    assert os.environ["PRAHARI_TEST_TOKEN"] == "secret-123"
    assert os.environ["PRAHARI_TEST_QUOTED"] == "qwen2.5:7b"
    assert os.environ["PRAHARI_TEST_EXISTING"] == "from-env"  # real env wins

    monkeypatch.delenv("PRAHARI_TEST_TOKEN")
    monkeypatch.delenv("PRAHARI_TEST_QUOTED")


def test_load_dotenv_missing_file_is_noop(tmp_path):
    load_dotenv(tmp_path / "does-not-exist.env")  # must not raise
