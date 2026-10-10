"""Feature schema, label set and adapter for the real CIC-IDS2017 CSV files."""
from __future__ import annotations

import numpy as np
import pandas as pd

# Network-communication features named in the project synopsis:
# protocol type, source/destination ports, packet counts, bytes, duration, rate.
FEATURES = [
    "protocol",         # IP protocol number (6 = TCP, 17 = UDP, 1 = ICMP)
    "src_port",
    "dst_port",
    "duration_ms",      # flow duration in milliseconds
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "packets_per_sec",
    "bytes_per_sec",
    "avg_pkt_size",
    "syn_count",
    "rst_count",
]

LABELS = ["BENIGN", "DDoS", "PortScan", "BruteForce"]

# Raw CIC-IDS2017 label -> project label. Anything not listed is dropped, because
# the project is scoped to DDoS, port scanning and brute-force attempts.
CIC_LABEL_MAP = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
}

# CIC-IDS2017 column (whitespace-stripped) -> project feature
CIC_COLUMN_MAP = {
    "Protocol": "protocol",
    "Source Port": "src_port",
    "Destination Port": "dst_port",
    "Flow Duration": "duration_ms",              # microseconds, converted below
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "Flow Packets/s": "packets_per_sec",
    "Flow Bytes/s": "bytes_per_sec",
    "Average Packet Size": "avg_pkt_size",
    "SYN Flag Count": "syn_count",
    "RST Flag Count": "rst_count",
    "Label": "label",
}


def derive_rates(df: pd.DataFrame) -> pd.DataFrame:
    """Fill the rate / size features from the raw counters."""
    df = df.copy()
    secs = np.maximum(df["duration_ms"].astype(float), 0.001) / 1000.0
    pkts = df["fwd_packets"].astype(float) + df["bwd_packets"].astype(float)
    byts = df["fwd_bytes"].astype(float) + df["bwd_bytes"].astype(float)
    df["packets_per_sec"] = pkts / secs
    df["bytes_per_sec"] = byts / secs
    df["avg_pkt_size"] = byts / np.maximum(pkts, 1.0)
    return df


def load_cic_ids2017(paths: list[str]) -> pd.DataFrame:
    """Read one or more CIC-IDS2017 CSVs and convert them to the project schema.

    Handles the usual quirks: padded column names, inf / NaN values, and
    attack classes outside the project's scope. If the CSV has no 'Source Port'
    column (the MachineLearningCVE release), src_port is filled with 0 and is
    later dropped automatically by feature selection.
    """
    frames = []
    for p in paths:
        raw = pd.read_csv(p, low_memory=False, encoding="latin-1")
        raw.columns = [c.strip() for c in raw.columns]
        frames.append(raw)
    raw = pd.concat(frames, ignore_index=True)

    raw["Label"] = raw["Label"].astype(str).str.strip()
    raw = raw[raw["Label"].isin(CIC_LABEL_MAP)].copy()
    raw["Label"] = raw["Label"].map(CIC_LABEL_MAP)

    df = pd.DataFrame(index=raw.index)
    for src, dst in CIC_COLUMN_MAP.items():
        if src in raw.columns:
            df[dst] = raw[src]
        else:
            df[dst] = 0
    df["duration_ms"] = pd.to_numeric(df["duration_ms"], errors="coerce") / 1000.0

    for c in FEATURES:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES + ["label"])
    return df[FEATURES + ["label"]].reset_index(drop=True)
