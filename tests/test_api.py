"""API tests (need fastapi, httpx, sqlalchemy and a trained model).
Run: python -m pytest tests/test_api.py
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["DATABASE_URL"] = "sqlite:///./test_threats.db"

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

if not (ROOT / "models" / "detector.joblib").exists():
    pytest.skip("train a model first: python scripts/train.py", allow_module_level=True)

from backend.app.main import app

DDOS = {"protocol": 6, "src_port": 51544, "dst_port": 80, "duration_ms": 40, "fwd_packets": 900,
        "bwd_packets": 3, "fwd_bytes": 54000, "bwd_bytes": 180, "syn_count": 40, "rst_count": 0}
NORMAL = {"protocol": 6, "src_port": 50000, "dst_port": 443, "duration_ms": 220, "fwd_packets": 8,
          "bwd_packets": 10, "fwd_bytes": 1400, "bwd_bytes": 9000, "syn_count": 1, "rst_count": 0}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:      # runs lifespan: creates tables, loads model
        c.delete("/api/detections")
        yield c
    Path("test_threats.db").unlink(missing_ok=True)


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["model_loaded"] is True


def test_predict_attack_and_normal(client):
    a = client.post("/api/predict", json=DDOS).json()
    n = client.post("/api/predict", json=NORMAL).json()
    assert a["status"] == "suspicious" and a["attack_type"] == "DDoS"
    assert a["severity_level"] in ("High", "Critical")
    assert n["status"] == "normal"


def test_validation_error(client):
    assert client.post("/api/predict", json={"dst_port": 99999}).status_code == 422


def test_simulate_history_and_stats(client):
    s = client.post("/api/simulate", json={"count": 50, "attack_ratio": 0.4}).json()
    assert s["generated"] == 50 and s["suspicious"] > 0
    rows = client.get("/api/detections", params={"limit": 10, "status": "suspicious"}).json()
    assert rows and all(r["status"] == "suspicious" for r in rows)
    st = client.get("/api/stats").json()
    assert st["total"] >= 52 and len(st["timeline"]) == 30


def test_model_info(client):
    payload = client.get("/api/model").json()
    assert "models" in payload
    assert "feature_selection" in payload
    assert "importance" in payload["feature_selection"]
    assert payload["best_model"] in payload["models"]


def test_model_retrains_after_new_detection(client):
    before = client.get("/api/model").json()
    client.post("/api/simulate", json={"count": 25, "attack_ratio": 0.7})
    after = client.get("/api/model").json()
    assert after["rows"] > before["rows"]
