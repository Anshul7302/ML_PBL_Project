#!/usr/bin/env python
"""Train and evaluate the threat-detection models (milestones 2-5, 9).

Usage
-----
  python scripts/train.py                          # synthetic quick-start data
  python scripts/train.py --csv data/*.csv         # real CIC-IDS2017 CSV files
  python scripts/train.py --rows 100000 --out models

Pipeline: load -> clean -> feature selection -> train Random Forest and XGBoost
-> compare -> fit Isolation Forest on benign traffic -> evaluate -> save bundle.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             precision_recall_fscore_support)
from sklearn.model_selection import train_test_split

from threatdetect.features import FEATURES, LABELS, load_cic_ids2017
from threatdetect.simulate import generate_flows
from threatdetect.detector import ANOMALY_THRESHOLD

try:
    from xgboost import XGBClassifier
    HAVE_XGB = True
except ImportError:  # keeps the script runnable where xgboost is not installed
    HAVE_XGB = False

SEED = 42


# ---------------------------------------------------------------- data / features
def load_data(args) -> tuple[pd.DataFrame, str]:
    if args.csv:
        paths = [str(p) for pat in args.csv for p in (Path().glob(pat) if "*" in pat else [Path(pat)])]
        print(f"[1/6] Loading {len(paths)} CIC-IDS2017 file(s)...")
        return load_cic_ids2017(paths), "CIC-IDS2017"
    print(f"[1/6] Generating {args.rows} synthetic flows (no --csv given)...")
    return generate_flows(args.rows, seed=SEED), "synthetic"


def select_features(X: pd.DataFrame, y: np.ndarray) -> tuple[list[str], dict]:
    """Drop constant, highly-correlated and low-importance features."""
    info = {"dropped_constant": [], "dropped_correlated": [], "dropped_low_importance": []}
    feats = list(X.columns)

    const = [c for c in feats if X[c].nunique() <= 1]
    info["dropped_constant"] = const
    feats = [c for c in feats if c not in const]

    corr = X[feats].corr().abs()
    drop = set()
    for i, a in enumerate(feats):
        if a in drop:
            continue
        for b in feats[i + 1:]:
            if b not in drop and corr.loc[a, b] > 0.97:
                drop.add(b)
    info["dropped_correlated"] = sorted(drop)
    feats = [c for c in feats if c not in drop]

    probe = RandomForestClassifier(n_estimators=60, max_depth=14, n_jobs=-1, random_state=SEED)
    probe.fit(X[feats], y)
    imp = pd.Series(probe.feature_importances_, index=feats).sort_values(ascending=False)
    keep = [c for c in feats if imp[c] >= 0.01]
    if len(keep) < 5:
        keep = list(imp.index[:5])
    info["dropped_low_importance"] = [c for c in feats if c not in keep]
    info["importance"] = {k: round(float(v), 4) for k, v in imp.items()}
    return keep, info


# ---------------------------------------------------------------- evaluation
def evaluate(name, model, X_te, y_te, classes) -> dict:
    pred = model.predict(X_te)
    p, r, f, _ = precision_recall_fscore_support(y_te, pred, average="macro", zero_division=0)
    cm = confusion_matrix(y_te, pred, labels=range(len(classes)))
    rep = classification_report(y_te, pred, labels=range(len(classes)), target_names=classes,
                                output_dict=True, zero_division=0)
    return {
        "name": name,
        "accuracy": round(float(accuracy_score(y_te, pred)), 4),
        "precision_macro": round(float(p), 4),
        "recall_macro": round(float(r), 4),
        "f1_macro": round(float(f), 4),
        "confusion_matrix": cm.tolist(),
        "per_class": {c: {k: round(float(rep[c][k]), 4) for k in ("precision", "recall", "f1-score")}
                      | {"support": int(rep[c]["support"])} for c in classes},
    }


def plot_cm(cm, classes, title, path):
    cm = np.array(cm)
    fig, ax = plt.subplots(figsize=(5.6, 4.8))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(classes)), classes, rotation=30, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title)
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, int(cm[i, j]), ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=9)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", nargs="*", help="CIC-IDS2017 CSV path(s) or glob(s)")
    ap.add_argument("--rows", type=int, default=60000, help="synthetic rows when no --csv")
    ap.add_argument("--max-rows", type=int, default=400000, help="subsample real data to this size")
    ap.add_argument("--out", default=str(ROOT / "models"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    df, source = load_data(args)
    if len(df) > args.max_rows:
        df = df.groupby("label", group_keys=False).apply(
            lambda g: g.sample(min(len(g), int(args.max_rows * len(g) / len(df)) + 1), random_state=SEED))
    classes = [c for c in LABELS if c in set(df["label"])]
    if "BENIGN" not in classes:
        sys.exit("Dataset has no BENIGN rows.")
    y = df["label"].map({c: i for i, c in enumerate(classes)}).to_numpy()
    X = df[FEATURES].astype(float)
    counts = df["label"].value_counts().to_dict()
    print("      class counts:", counts)

    print("[2/6] Selecting features...")
    selected, fs_info = select_features(X, y)
    print("      selected:", selected)

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=SEED)

    print("[3/6] Training models...")
    candidates = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=18, min_samples_leaf=2,
            class_weight="balanced", n_jobs=-1, random_state=SEED),
    }
    if HAVE_XGB:
        candidates["XGBoost"] = XGBClassifier(
            n_estimators=250, max_depth=6, learning_rate=0.1, subsample=0.9,
            colsample_bytree=0.9, tree_method="hist", eval_metric="mlogloss",
            n_jobs=-1, random_state=SEED)
    else:
        print("      xgboost not installed -> using HistGradientBoosting as a stand-in "
              "(run `pip install xgboost` for the real thing)")
        candidates["XGBoost (stand-in: HistGradientBoosting)"] = HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.1, class_weight="balanced", random_state=SEED)

    results, fitted = {}, {}
    for name, m in candidates.items():
        t0 = time.time()
        m.fit(X_tr[selected], y_tr)
        res = evaluate(name, m, X_te[selected], y_te, classes)
        res["train_seconds"] = round(time.time() - t0, 2)
        results[name], fitted[name] = res, m
        print(f"      {name:<42} acc={res['accuracy']:.4f}  macro-F1={res['f1_macro']:.4f}  "
              f"({res['train_seconds']}s)")

    best = max(results, key=lambda k: results[k]["f1_macro"])
    print(f"      best model: {best}")

    print("[4/6] Training Isolation Forest on benign traffic...")
    benign_idx = np.where(y_tr == classes.index("BENIGN"))[0]
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=SEED, n_jobs=-1)
    iso.fit(X_tr.iloc[benign_idx][selected])
    ben_scores = iso.decision_function(X_tr.iloc[benign_idx][selected])
    iso_median, iso_low = float(np.median(ben_scores)), float(np.percentile(ben_scores, 1))

    s = iso.decision_function(X_te[selected])
    anom = np.clip((iso_median - s) / max(iso_median - iso_low, 1e-9), 0, 1)
    flagged = anom >= ANOMALY_THRESHOLD
    is_benign = y_te == classes.index("BENIGN")
    anomaly_eval = {
        "threshold": ANOMALY_THRESHOLD,
        "false_positive_rate_on_benign": round(float(flagged[is_benign].mean()), 4),
        "attack_detection_rate": round(float(flagged[~is_benign].mean()), 4),
    }
    print("      ", anomaly_eval)

    print("[5/6] Writing artifacts...")
    bundle = {
        "model": fitted[best], "model_name": best, "classes": classes,
        "selected_features": selected, "all_features": FEATURES,
        "isolation_forest": iso, "iso_median": iso_median, "iso_low": iso_low,
    }
    joblib.dump(bundle, out / "detector.joblib", compress=3)

    metrics = {
        "dataset": source, "rows": int(len(df)), "class_counts": {k: int(v) for k, v in counts.items()},
        "classes": classes, "feature_selection": fs_info, "selected_features": selected,
        "models": results, "best_model": best, "anomaly_detection": anomaly_eval,
        "xgboost_available": HAVE_XGB,
    }
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2))
    plot_cm(results[best]["confusion_matrix"], classes, f"{best} - confusion matrix", out / "confusion_matrix.png")

    print("[6/6] Done. Artifacts in", out)


if __name__ == "__main__":
    main()
