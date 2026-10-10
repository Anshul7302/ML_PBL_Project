"""Synthetic traffic generator.

Produces flow records in the same schema as the CIC-IDS2017 adapter so the whole
pipeline works without downloading a multi-GB dataset. It is used for (a) a
quick-start training set and (b) the live "simulate traffic" feature of the
dashboard. For the real evaluation, train on CIC-IDS2017 / UNSW-NB15
(see README).

Classes deliberately overlap (e.g. low-rate DDoS, long benign SSH sessions,
benign DNS bursts) so the models are not trivially perfect.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .features import FEATURES, LABELS, derive_rates

COMMON_PORTS = np.array([80, 443, 53, 22, 25, 110, 143, 8080, 3306, 123, 993, 445])
COMMON_P = np.array([0.30, 0.34, 0.12, 0.05, 0.03, 0.01, 0.01, 0.04, 0.02, 0.03, 0.02, 0.03])
COMMON_P = COMMON_P / COMMON_P.sum()


def _lognormal_int(rng, mean, sigma, n, lo=1, hi=None):
    v = np.rint(rng.lognormal(mean, sigma, n)).astype(float)
    return np.clip(v, lo, hi if hi is not None else np.inf)


def _benign(rng, n):
    proto = rng.choice([6, 17, 1], n, p=[0.78, 0.20, 0.02])
    dst = rng.choice(COMMON_PORTS, n, p=COMMON_P)
    dur = rng.lognormal(5.2, 1.7, n)                       # median ~180 ms
    fwd = _lognormal_int(rng, 1.9, 1.0, n, 1, 3000)
    bwd = _lognormal_int(rng, 2.1, 1.1, n, 0, 5000)
    size = rng.lognormal(5.6, 0.9, n).clip(40, 1500)
    return pd.DataFrame({
        "protocol": proto,
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": dst,
        "duration_ms": dur,
        "fwd_packets": fwd,
        "bwd_packets": bwd,
        "fwd_bytes": fwd * size * rng.uniform(0.3, 1.0, n),
        "bwd_bytes": bwd * size * rng.uniform(0.6, 1.4, n),
        "syn_count": rng.choice([0, 1, 2], n, p=[0.35, 0.60, 0.05]),
        "rst_count": rng.choice([0, 1], n, p=[0.93, 0.07]),
    })


def _ddos(rng, n):
    low = rng.random(n) < 0.12                              # low-rate variants look benign-ish
    fwd = np.where(low, _lognormal_int(rng, 2.5, 0.8, n), _lognormal_int(rng, 5.5, 1.2, n, 20, 20000))
    bwd = np.where(low, _lognormal_int(rng, 1.8, 0.8, n, 0), _lognormal_int(rng, 1.0, 1.0, n, 0, 40))
    dur = np.where(low, rng.lognormal(6.0, 1.2, n), rng.lognormal(3.2, 1.6, n))
    size = rng.lognormal(4.3, 0.5, n).clip(40, 400)
    return pd.DataFrame({
        "protocol": rng.choice([6, 17], n, p=[0.85, 0.15]),
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.choice([80, 443, 8080, 53], n, p=[0.55, 0.30, 0.10, 0.05]),
        "duration_ms": dur,
        "fwd_packets": fwd,
        "bwd_packets": bwd,
        "fwd_bytes": fwd * size,
        "bwd_bytes": bwd * rng.uniform(40, 200, n),
        "syn_count": np.where(low, rng.integers(0, 3, n), rng.integers(2, 60, n)),
        "rst_count": rng.choice([0, 1, 2], n, p=[0.70, 0.20, 0.10]),
    })


def _portscan(rng, n):
    closed = rng.random(n) < 0.8
    fwd = rng.choice([1, 2, 3], n, p=[0.80, 0.15, 0.05]).astype(float)
    bwd = np.where(closed, rng.choice([0, 1], n, p=[0.3, 0.7]), 1).astype(float)
    return pd.DataFrame({
        "protocol": rng.choice([6, 17], n, p=[0.95, 0.05]),
        "src_port": rng.integers(30000, 65535, n),
        "dst_port": rng.integers(1, 65535, n),
        "duration_ms": rng.lognormal(0.8, 1.2, n),         # a few ms
        "fwd_packets": fwd,
        "bwd_packets": bwd,
        "fwd_bytes": fwd * rng.uniform(40, 70, n),
        "bwd_bytes": bwd * rng.uniform(0, 60, n),
        "syn_count": np.where(rng.random(n) < 0.9, 1, 0),
        "rst_count": np.where(closed, 1, 0),
    })


def _bruteforce(rng, n):
    fwd = _lognormal_int(rng, 2.8, 0.5, n, 6, 80)
    bwd = _lognormal_int(rng, 2.7, 0.5, n, 5, 80)
    return pd.DataFrame({
        "protocol": np.full(n, 6),
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.choice([22, 21, 3389, 23, 5900], n, p=[0.50, 0.25, 0.15, 0.05, 0.05]),
        "duration_ms": rng.lognormal(7.6, 0.8, n),         # ~2 s per attempt
        "fwd_packets": fwd,
        "bwd_packets": bwd,
        "fwd_bytes": fwd * rng.uniform(55, 130, n),
        "bwd_bytes": bwd * rng.uniform(55, 140, n),
        "syn_count": rng.choice([1, 2], n, p=[0.85, 0.15]),
        "rst_count": rng.choice([0, 1], n, p=[0.55, 0.45]),
    })


_GENERATORS = {"BENIGN": _benign, "DDoS": _ddos, "PortScan": _portscan, "BruteForce": _bruteforce}


def generate_flows(n: int = 10000, mix: dict | None = None, seed: int | None = 42,
                   shuffle: bool = True) -> pd.DataFrame:
    """Generate `n` labelled flows. `mix` maps label -> proportion (normalised)."""
    rng = np.random.default_rng(seed)
    mix = mix or {"BENIGN": 0.70, "DDoS": 0.12, "PortScan": 0.10, "BruteForce": 0.08}
    total = sum(mix.values())
    labels = list(mix)
    counts = [int(round(n * mix[l] / total)) for l in labels]
    counts[0] += n - sum(counts)                           # absorb rounding in first class
    parts = []
    for lab, c in zip(labels, counts):
        if c <= 0:
            continue
        d = _GENERATORS[lab](rng, c)
        d["label"] = lab
        parts.append(d)
    df = pd.concat(parts, ignore_index=True)
    df = derive_rates(df)
    df = df[FEATURES + ["label"]]
    if shuffle:
        df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df


def random_ips(rng: np.random.Generator, label: str) -> tuple[str, str]:
    """Plausible src/dst IPs for the dashboard (attackers external, victims internal)."""
    internal = f"10.0.{rng.integers(0, 4)}.{rng.integers(2, 250)}"
    external = f"{rng.choice([45, 91, 103, 185, 198])}.{rng.integers(1, 250)}.{rng.integers(1, 250)}.{rng.integers(2, 250)}"
    if label == "BENIGN":
        return (internal, f"{rng.choice([142, 151, 172])}.{rng.integers(1, 250)}.{rng.integers(1, 250)}.{rng.integers(2, 250)}") \
            if rng.random() < 0.6 else (internal, f"10.0.{rng.integers(0, 4)}.{rng.integers(2, 250)}")
    return external, internal
