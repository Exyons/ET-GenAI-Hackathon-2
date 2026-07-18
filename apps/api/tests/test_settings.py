from fastapi.testclient import TestClient

from prahari.attribute import llm
from prahari.live import settings as settings_store
from prahari.main import app

client = TestClient(app)


def test_settings_roundtrip_and_key_masked():
    r = client.get("/api/settings").json()
    assert r["provider"] == "ollama" and r["api_key"] == "" and r["api_key_set"] is False
    assert "ollama_cloud" in r["providers"]

    client.put("/api/settings", json={"provider": "openai", "base_url": "https://api.x.test",
                                       "api_key": "sk-secret", "chat_model": "gpt-x"})
    r = client.get("/api/settings").json()
    assert r["provider"] == "openai" and r["chat_model"] == "gpt-x"
    assert r["api_key_set"] is True and r["api_key"] == ""  # never leaked back
    assert settings_store.get()["api_key"] == "sk-secret"   # but stored


def test_put_rejects_unknown_provider():
    assert client.put("/api/settings", json={"provider": "hal9000"}).status_code == 400


def test_llm_chat_ollama_uses_settings(monkeypatch):
    settings_store.update({"provider": "ollama", "base_url": "http://h:1", "chat_model": "m1", "api_key": ""})
    seen = {}
    monkeypatch.setattr(llm, "ollama_chat",
                        lambda p, model, host, api_key=None: seen.update(model=model, host=host, key=api_key) or "ok")
    assert llm.chat("hi") == "ok"
    assert seen == {"model": "m1", "host": "http://h:1", "key": None}


def test_llm_chat_openai_path(monkeypatch):
    settings_store.update({"provider": "openai", "base_url": "https://api.x.test",
                           "api_key": "sk", "chat_model": "gpt-x"})

    class Resp:
        is_error = False
        def json(self):
            return {"choices": [{"message": {"content": "hello"}}]}

    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured.update(url=url, headers=headers, model=json["model"])
        return Resp()

    monkeypatch.setattr(llm.httpx, "post", fake_post)
    assert llm.chat("hi") == "hello"
    assert captured["url"] == "https://api.x.test/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer sk" and captured["model"] == "gpt-x"


def test_test_connection_reports_error(monkeypatch):
    settings_store.update({"provider": "ollama", "base_url": "http://127.0.0.1:1", "chat_model": "m"})
    monkeypatch.setattr(llm, "chat", lambda p, s=None: (_ for _ in ()).throw(OSError("refused")))
    r = llm.test_connection()
    assert r["ok"] is False and "OSError" in r["error"]
