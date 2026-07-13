from fastapi.testclient import TestClient

from prahari.main import app

client = TestClient(app)


def test_metrics_endpoint():
    r = client.get("/api/metrics")
    assert r.status_code == 200
    assert r.json()["signature_recall"] == 0.0
    assert r.json()["behavioural_recall"] > 0.5


def test_incidents_list_sorted_and_c553_present():
    r = client.get("/api/demo/incidents")
    assert r.status_code == 200
    data = r.json()
    ids = [i["id"] for i in data]
    assert "inc-c553" in ids
    scores = [i["compound_score"] for i in data]
    assert scores == sorted(scores, reverse=True)
    assert data[0]["id"] == "inc-c553"  # highest compound


def test_incident_detail_and_404():
    r = client.get("/api/incidents/inc-c553")
    assert r.status_code == 200
    body = r.json()
    assert body["attribution"]["technique_ids"][0] == "T1021.006"
    assert len(body["timeline"]) == 3
    assert client.get("/api/incidents/nope").status_code == 404
