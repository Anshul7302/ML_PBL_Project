import sys
from argparse import Namespace
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import train as train_module


def test_load_data_prefers_real_dataset_when_csv_exists(monkeypatch):
    csv_path = ROOT / "data" / "test_real_dataset.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.write_text(
        "Label,Protocol,Source Port,Destination Port,Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Flow Packets/s,Flow Bytes/s,Average Packet Size,SYN Flag Count,RST Flag Count\n"
        "BENIGN,6,1000,80,100,5,2,1200,500,100,5000,200,0,0\n"
        "DDoS,6,5000,80,200,44,3,8000,400,400,10000,180,10,0\n",
        encoding="utf-8",
    )

    sentinel = pd.DataFrame({"label": ["BENIGN"]})
    monkeypatch.setattr(train_module, "load_cic_ids2017", lambda paths: sentinel)
    args = Namespace(csv=None, synthetic=False, rows=10)

    try:
        df, source = train_module.load_data(args)
    finally:
        csv_path.unlink(missing_ok=True)

    assert source == "CIC-IDS2017"
    assert df is sentinel


def test_load_data_requires_explicit_synthetic_mode_without_dataset(monkeypatch):
    for csv_file in sorted((ROOT / "data").glob("*.csv")):
        csv_file.unlink()

    monkeypatch.setattr(train_module, "generate_flows", lambda rows, seed=None: pd.DataFrame({"label": ["BENIGN"]}))
    args = Namespace(csv=None, synthetic=False, rows=10)

    with pytest.raises(FileNotFoundError):
        train_module.load_data(args)
