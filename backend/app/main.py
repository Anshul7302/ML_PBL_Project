"""FastAPI backend: accepts flows, runs the ML model, stores and serves detections."""
import json
import os
import sys
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from threatdetect import FEATURES, ThreatDetector                      # noqa: E402
from threatdetect.features import derive_rates                          # noqa: E402
from threatdetect.simulate import generate_flows, random_ips            # noqa: E402

from . import models, schemas                                           # noqa: E402
from .db import Base, engine, get_db                                    # noqa: E402

MODEL_DIR = Path(os.getenv("MODEL_DIR", ROOT / "models"))
state: dict = {"detector": None, "last_retrained_rows": 0}


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    path = MODEL_DIR / "detector.joblib"
    if path.exists():
        state["detector"] = ThreatDetector.load(path)
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(title="AI-Powered Cybersecurity Threat Detection API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_methods=["*"], allow_headers=["*"],
)


def get_detector() -> ThreatDetector:
    if state["detector"] is None:
        raise HTTPException(503, "Model not loaded. Run `python scripts/train.py` first.")
    return state["detector"]


def _store(db: Session, flows: list[dict], results: list[dict]) -> list[models.Detection]:
    rows = []
    for f, r in zip(flows, results):
        row = models.Detection(
            src_ip=f.get("src_ip"), dst_ip=f.get("dst_ip"),
            protocol=int(f["protocol"]), src_port=int(f["src_port"]), dst_port=int(f["dst_port"]),
            status=r["status"], attack_type=r["attack_type"], confidence=r["confidence"],
            anomaly_score=r["anomaly_score"], severity_score=r["severity_score"],
            severity_level=r["severity_level"], is_suspicious=r["status"] == "suspicious",
            features={k: round(float(f[k]), 3) for k in FEATURES}, probabilities=r["probabilities"],
        )
        db.add(row)
        rows.append(row)
    db.commit()
    return rows


def _analyse(db: Session, det: ThreatDetector, flows: list[dict]) -> list[models.Detection]:
    df = derive_rates(pd.DataFrame(flows))
    results = det.predict_df(df)
    enriched = df.to_dict("records")
    for e, f in zip(enriched, flows):
        e["src_ip"], e["dst_ip"] = f.get("src_ip"), f.get("dst_ip")
    rows = _store(db, enriched, results)
    total_rows = db.scalar(select(func.count(models.Detection.id))) or 0
    if total_rows - state.get("last_retrained_rows", 0) >= 10:
        _retrain_from_db(db)
    return rows


def _retrain_from_db(db: Session):
    """Refresh the live model from all stored detections when enough new entries accumulate."""
    stored = db.scalars(select(models.Detection)).all()
    if not stored:
        return

    frame = pd.DataFrame([d.features for d in stored])
    frame["label"] = [d.attack_type for d in stored]
    frame = frame.replace([np.inf, -np.inf], np.nan).dropna()
    if frame.empty or "BENIGN" not in set(frame["label"]):
        return

    labels = sorted(set(frame["label"]))
    y = frame["label"].map({label: i for i, label in enumerate(labels)}).to_numpy()
    X = frame[FEATURES].astype(float)
    selected = [c for c in FEATURES if c in X.columns and X[c].nunique() > 1]
    if len(selected) < 2:
        return

    if np.min(np.bincount(y)) >= 2 and len(np.unique(y)) > 1:
        X_tr, X_te, y_tr, y_te = train_test_split(X[selected], y, test_size=0.25, stratify=y, random_state=42)
    else:
        X_tr, X_te, y_tr, y_te = X[selected], X[selected], y, y

    model = RandomForestClassifier(n_estimators=200, max_depth=18, min_samples_leaf=2,
                                  class_weight="balanced", n_jobs=-1, random_state=42)
    model.fit(X_tr, y_tr)
    pred = model.predict(X_te)
    p, r, f, _ = precision_recall_fscore_support(y_te, pred, average="macro", zero_division=0)
    cm = confusion_matrix(y_te, pred, labels=range(len(labels)))
    rep = __import__("sklearn.metrics").metrics.classification_report(
        y_te, pred, labels=range(len(labels)), target_names=labels, output_dict=True, zero_division=0
    )

    feature_importance = pd.Series(model.feature_importances_, index=selected).sort_values(ascending=False)
    result = {
        "name": "RandomForestClassifier",
        "accuracy": round(float(accuracy_score(y_te, pred)), 4),
        "precision_macro": round(float(p), 4),
        "recall_macro": round(float(r), 4),
        "f1_macro": round(float(f), 4),
        "train_seconds": 0.0,
        "confusion_matrix": cm.tolist(),
        "per_class": {c: {k: round(float(rep[c][k]), 4) for k in ("precision", "recall", "f1-score")} | {"support": int(rep[c]["support"])} for c in labels},
    }

    feature_selection = {
        "dropped_constant": [],
        "dropped_correlated": [],
        "dropped_low_importance": [],
        "importance": {k: round(float(v), 4) for k, v in feature_importance.items()},
    }

    if "BENIGN" in labels:
        benign_idx = np.where(y_tr == labels.index("BENIGN"))[0]
        iso = IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=-1)
        iso.fit(X_tr.iloc[benign_idx][selected])
        ben_scores = iso.decision_function(X_tr.iloc[benign_idx][selected])
        iso_median, iso_low = float(np.median(ben_scores)), float(np.percentile(ben_scores, 1))

        s = iso.decision_function(X_te[selected])
        anom = np.clip((iso_median - s) / max(iso_median - iso_low, 1e-9), 0, 1)
        flagged = anom >= 0.8
        is_benign = y_te == labels.index("BENIGN")
        anomaly_eval = {
            "threshold": 0.8,
            "false_positive_rate_on_benign": round(float(flagged[is_benign].mean()), 4),
            "attack_detection_rate": round(float(flagged[~is_benign].mean()), 4),
        }
    else:
        iso = IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=-1)
        iso.fit(X_tr[selected])
        iso_median, iso_low = 0.0, 0.0
        anomaly_eval = {"threshold": 0.8, "false_positive_rate_on_benign": 0.0, "attack_detection_rate": 0.0}

    metrics = {
        "dataset": "database_retrain",
        "rows": int(len(frame)),
        "class_counts": {k: int(v) for k, v in frame["label"].value_counts().items()},
        "classes": labels,
        "feature_selection": feature_selection,
        "selected_features": selected,
        "models": {"RandomForestClassifier": result},
        "best_model": "RandomForestClassifier",
        "anomaly_detection": anomaly_eval,
        "xgboost_available": False,
    }

    bundle = {
        "model": model,
        "model_name": "RandomForestClassifier",
        "classes": labels,
        "selected_features": selected,
        "all_features": FEATURES,
        "isolation_forest": iso,
        "iso_median": iso_median,
        "iso_low": iso_low,
    }
    joblib.dump(bundle, MODEL_DIR / "detector.joblib", compress=3)
    (MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    state["detector"] = ThreatDetector(bundle)
    state["last_retrained_rows"] = int(len(frame))


# ------------------------------------------------------------------ endpoints
@app.get("/api/health")
def health():
    return {"status": "ok", "model_loaded": state["detector"] is not None,
            "model": state["detector"].model_name if state["detector"] else None}


@app.post("/api/predict", response_model=schemas.DetectionOut)
def predict(flow: schemas.FlowIn, db: Session = Depends(get_db), det: ThreatDetector = Depends(get_detector)):
    """Classify one flow, store the result and return it."""
    return _analyse(db, det, [flow.model_dump()])[0]


@app.post("/api/predict/batch", response_model=list[schemas.DetectionOut])
def predict_batch(flows: list[schemas.FlowIn], db: Session = Depends(get_db),
                  det: ThreatDetector = Depends(get_detector)):
    if not flows or len(flows) > 1000:
        raise HTTPException(422, "Send between 1 and 1000 flows.")
    return _analyse(db, det, [f.model_dump() for f in flows])


@app.post("/api/simulate", response_model=schemas.SimulateOut)
def simulate(body: schemas.SimulateIn, db: Session = Depends(get_db),
             det: ThreatDetector = Depends(get_detector)):
    """Generate sample traffic, run it through the model and store it (demo mode)."""
    rng = np.random.default_rng()
    atk = body.attack_ratio
    mix = {"BENIGN": 1 - atk, "DDoS": atk * 0.4, "PortScan": atk * 0.35, "BruteForce": atk * 0.25}
    mix = {k: v for k, v in mix.items() if v > 0}
    df = generate_flows(body.count, mix=mix, seed=int(rng.integers(0, 2**31)))
    flows = df.drop(columns=["label"]).to_dict("records")
    for f, lab in zip(flows, df["label"]):
        f["src_ip"], f["dst_ip"] = random_ips(rng, lab)
    rows = _analyse(db, det, flows)
    return {"generated": len(rows), "suspicious": sum(r.is_suspicious for r in rows), "detections": rows}


@app.get("/api/detections", response_model=list[schemas.DetectionOut])
def list_detections(
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
    status: str | None = Query(None, pattern="^(normal|suspicious)$"),
    attack_type: str | None = None, severity: str | None = None,
    db: Session = Depends(get_db),
):
    q = select(models.Detection).order_by(models.Detection.id.desc())
    if status:
        q = q.where(models.Detection.status == status)
    if attack_type:
        q = q.where(models.Detection.attack_type == attack_type)
    if severity:
        q = q.where(models.Detection.severity_level == severity)
    return db.scalars(q.limit(limit).offset(offset)).all()


@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count(models.Detection.id))) or 0
    suspicious = db.scalar(select(func.count(models.Detection.id)).where(models.Detection.is_suspicious.is_(True))) or 0
    by_attack = dict(db.execute(
        select(models.Detection.attack_type, func.count()).group_by(models.Detection.attack_type)).all())
    by_sev = dict(db.execute(
        select(models.Detection.severity_level, func.count()).group_by(models.Detection.severity_level)).all())
    avg_sev = db.scalar(select(func.avg(models.Detection.severity_score)).where(
        models.Detection.is_suspicious.is_(True)))

    # per-minute timeline for the last 30 minutes
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    since = now - timedelta(minutes=29)
    recent = db.execute(select(models.Detection.created_at, models.Detection.is_suspicious)
                        .where(models.Detection.created_at >= since)).all()
    buckets = defaultdict(lambda: [0, 0])
    for ts, sus in recent:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        buckets[ts.replace(second=0, microsecond=0)][1 if sus else 0] += 1
    timeline = []
    for i in range(30):
        t = since + timedelta(minutes=i)
        n, s = buckets[t]
        timeline.append({"time": t.strftime("%H:%M"), "normal": n, "suspicious": s})

    return {
        "total": total, "suspicious": suspicious, "normal": total - suspicious,
        "suspicious_rate": round(suspicious / total, 4) if total else 0.0,
        "avg_severity": round(float(avg_sev), 1) if avg_sev is not None else 0.0,
        "by_attack": by_attack, "by_severity": by_sev, "timeline": timeline,
    }


@app.get("/api/model")
def model_info():
    """Training metrics (accuracy, precision, recall, F1, confusion matrix) for the dashboard."""
    p = MODEL_DIR / "metrics.json"
    if not p.exists():
        raise HTTPException(404, "metrics.json not found. Run `python scripts/train.py` first.")
    return json.loads(p.read_text())


@app.get("/api/model/confusion-matrix.png")
def confusion_png():
    p = MODEL_DIR / "confusion_matrix.png"
    if not p.exists():
        raise HTTPException(404, "not found")
    return FileResponse(p, media_type="image/png")


@app.delete("/api/detections", status_code=204)
def clear_detections(db: Session = Depends(get_db)):
    db.execute(delete(models.Detection))
    db.commit()
