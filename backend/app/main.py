"""FastAPI backend: accepts flows, runs the ML model, stores and serves detections."""
import json
import os
import sys
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
state: dict = {"detector": None}


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
    import pandas as pd
    df = derive_rates(pd.DataFrame(flows))
    results = det.predict_df(df)
    enriched = df.to_dict("records")
    for e, f in zip(enriched, flows):
        e["src_ip"], e["dst_ip"] = f.get("src_ip"), f.get("dst_ip")
    return _store(db, enriched, results)


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
