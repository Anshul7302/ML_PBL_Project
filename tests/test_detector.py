"""ML-core tests. Run: python -m pytest tests/  (needs models/detector.joblib: run scripts/train.py first)"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest

from threatdetect import ThreatDetector
from threatdetect.detector import severity_level, threat_score
from threatdetect.simulate import generate_flows

MODEL = ROOT / "models" / "detector.joblib"


@pytest.fixture(scope="module")
def det():
    if not MODEL.exists():
        pytest.skip("train a model first: python scripts/train.py")
    return ThreatDetector.load(MODEL)


def test_prediction_schema(det):
    df = generate_flows(20, seed=1)
    res = det.predict_df(df)
    assert len(res) == 20
    for r in res:
        assert r["status"] in ("normal", "suspicious")
        assert 0 <= r["confidence"] <= 1
        assert 0 <= r["severity_score"] <= 100
        assert abs(sum(r["probabilities"].values()) - 1) < 0.01


def test_attack_detection_on_fresh_data(det):
    df = generate_flows(3000, seed=999)          # unseen seed
    res = det.predict_df(df)
    y_true = df["label"].tolist()
    acc = sum(r["attack_type"] == t for r, t in zip(res, y_true)) / len(res)
    assert acc > 0.90
    sus_true = [t != "BENIGN" for t in y_true]
    recall = sum(r["status"] == "suspicious" for r, s in zip(res, sus_true) if s) / sum(sus_true)
    assert recall > 0.90


def test_ddos_scores_higher_than_benign(det):
    df = generate_flows(600, mix={"BENIGN": 0.5, "DDoS": 0.5}, seed=7)
    res = det.predict_df(df)
    ddos = [r["severity_score"] for r, l in zip(res, df["label"]) if l == "DDoS"]
    ben = [r["severity_score"] for r, l in zip(res, df["label"]) if l == "BENIGN"]
    assert sum(ddos) / len(ddos) > 60 > sum(ben) / len(ben)


def test_severity_levels():
    assert severity_level(90, True) == "Critical"
    assert severity_level(65, True) == "High"
    assert severity_level(40, True) == "Medium"
    assert severity_level(10, True) == "Low"
    assert severity_level(10, False) == "None"


def test_threat_score_bounds():
    assert threat_score("DDoS", 1.0, 1.0) == 100.0
    assert threat_score("BENIGN", 0.0, 0.0) == 0.0
    assert 0 <= threat_score("PortScan", 0.6, 0.2) <= 100
