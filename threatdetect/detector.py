"""Inference: classification + anomaly detection + threat-severity scoring."""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .features import FEATURES

# How dangerous each attack class is, used to weight the severity score.
ATTACK_WEIGHT = {"DDoS": 1.0, "BruteForce": 0.85, "PortScan": 0.70, "Anomaly": 0.55}
ANOMALY_THRESHOLD = 0.80   # anomaly_score above this flags otherwise-"benign" traffic


def severity_level(score: float, suspicious: bool) -> str:
    if not suspicious:
        return "None"
    if score >= 85:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def threat_score(label: str, p_attack: float, anomaly: float) -> float:
    """Severity 0-100 from attack type, classifier certainty and anomaly score."""
    if label in ATTACK_WEIGHT and label != "Anomaly":
        raw = ATTACK_WEIGHT[label] * (0.75 * p_attack + 0.25 * anomaly)
    elif label == "Anomaly":
        raw = ATTACK_WEIGHT["Anomaly"] * anomaly
    else:  # normal traffic: small residual risk
        raw = 0.15 * max(p_attack, anomaly)
    return round(float(np.clip(raw, 0, 1)) * 100, 1)


class ThreatDetector:
    def __init__(self, bundle: dict):
        self.bundle = bundle
        self.model = bundle["model"]
        self.iso = bundle["isolation_forest"]
        self.classes: list[str] = bundle["classes"]
        self.features: list[str] = bundle["selected_features"]
        self.iso_median: float = bundle["iso_median"]
        self.iso_low: float = bundle["iso_low"]
        self.model_name: str = bundle["model_name"]
        self.benign_idx = self.classes.index("BENIGN")

    @classmethod
    def load(cls, path: str | Path) -> "ThreatDetector":
        return cls(joblib.load(path))

    # ------------------------------------------------------------------ #
    def anomaly_scores(self, X: pd.DataFrame) -> np.ndarray:
        """0 = typical benign traffic, 1 = as unusual as the rarest 1% of benign."""
        s = self.iso.decision_function(X[self.features])          # higher = more normal
        span = max(self.iso_median - self.iso_low, 1e-9)
        return np.clip((self.iso_median - s) / span, 0.0, 1.0)

    def predict_df(self, df: pd.DataFrame) -> list[dict]:
        X = df[FEATURES].astype(float)
        proba = self.model.predict_proba(X[self.features])
        anom = self.anomaly_scores(X)
        out = []
        for p, a in zip(proba, anom):
            idx = int(np.argmax(p))
            label = self.classes[idx]
            p_attack = float(1.0 - p[self.benign_idx])
            if label != "BENIGN":
                suspicious, attack = True, label
            elif a >= ANOMALY_THRESHOLD:
                suspicious, attack = True, "Anomaly"
            else:
                suspicious, attack = False, "BENIGN"
            score = threat_score(attack, p_attack, float(a))
            out.append({
                "status": "suspicious" if suspicious else "normal",
                "attack_type": attack,
                "confidence": round(float(p[idx]), 4),
                "attack_probability": round(p_attack, 4),
                "anomaly_score": round(float(a), 4),
                "severity_score": score,
                "severity_level": severity_level(score, suspicious),
                "probabilities": {c: round(float(v), 4) for c, v in zip(self.classes, p)},
            })
        return out

    def predict(self, flows: list[dict]) -> list[dict]:
        return self.predict_df(pd.DataFrame(flows))
