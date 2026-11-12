# AI-Powered Cybersecurity Threat Detection System

Team **Deemed Developers** · PBL Year 2 Sem 3

A Machine Learning prototype that analyses network-traffic flows, flags them as **normal** or **suspicious**,
classifies the attack (**DDoS**, **port scan**, **brute force**), computes a **0-100 severity score**, stores
every detection in **PostgreSQL**, and shows everything in a **React dashboard**.

```
Dataset / traffic → preprocessing → feature selection → Random Forest / XGBoost
        → normal vs suspicious → attack classification (+ Isolation Forest anomaly score)
        → severity scoring → FastAPI → PostgreSQL (history) + React dashboard (alerts)
```

## Project layout

| Path | What it is | Synopsis milestone |
|---|---|---|
| `threatdetect/features.py` | feature schema, CIC-IDS2017 loader/cleaner | 1-3 |
| `threatdetect/simulate.py` | synthetic traffic generator (quick-start data + dashboard demo) | 1-2 |
| `scripts/train.py` | feature selection, RF vs XGBoost training, Isolation Forest, evaluation | 3-5, 9 |
| `threatdetect/detector.py` | inference, anomaly score, threat-severity scoring | 5 |
| `backend/app/` | FastAPI API + SQLAlchemy models (PostgreSQL) | 6 |
| `frontend/` | React + Recharts dashboard | 7 |
| `tests/` | ML and API tests | 9 |
| `docker-compose.yml` | Postgres + API + dashboard in one command | 8 |

## Quick start (Docker)

```bash
docker compose up --build
# dashboard: http://localhost:5173     API docs: http://localhost:8000/docs
```
The app prefers the real dataset in `data/*.csv`. If no CSV files are present, Docker will use the explicit synthetic demo mode instead of silently training on fake data.

## Quick start (manual)

```bash
# 1. ML + API dependencies
pip install -r requirements.txt -r backend/requirements.txt

# 2. Add CIC-IDS2017 CSV files into data/ and train on the real dataset
python scripts/train.py

# If you do not have the real dataset yet, use the synthetic demo mode explicitly
python scripts/train.py --synthetic --rows 60000

# 3. API (SQLite by default; set DATABASE_URL for PostgreSQL)
export DATABASE_URL=postgresql+psycopg2://user:pass@localhost:5432/threatdb   # optional
uvicorn backend.app.main:app --reload --port 8000

# 4. Dashboard
cd frontend && npm install && npm run dev        # http://localhost:5173
```

In the dashboard press **Simulate 30 flows** or **Start live monitor** to push traffic through the model.

## Using the real dataset (recommended for your report)

The synthetic generator exists so the project runs out of the box. For genuine results, download
**CIC-IDS2017** (MachineLearningCVE CSVs from the Canadian Institute for Cybersecurity) into `data/` and run:

```bash
python scripts/train.py --csv "data/*.csv"
```
The loader strips the padded column names, removes inf/NaN rows, keeps only BENIGN / DDoS / PortScan /
FTP-Patator + SSH-Patator (→ BruteForce), and maps columns onto the project's 13 features. Put the real
numbers from `models/metrics.json` in your report - **the synthetic-data scores are not a real evaluation.**
UNSW-NB15 can be supported by adding a column map next to `CIC_COLUMN_MAP` in `features.py`.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/predict` | classify one flow, store it |
| POST | `/api/predict/batch` | classify up to 1000 flows |
| POST | `/api/simulate` | generate demo traffic and classify it |
| GET | `/api/detections` | history, filter by `status`, `attack_type`, `severity` |
| GET | `/api/stats` | totals, per-attack/severity counts, 30-min timeline |
| GET | `/api/model` | accuracy / precision / recall / F1 / confusion matrix |
| GET | `/api/health` | liveness + model status |

Example:
```bash
curl -X POST localhost:8000/api/predict -H 'Content-Type: application/json' -d '{
  "protocol":6,"src_port":51544,"dst_port":80,"duration_ms":40,"fwd_packets":900,
  "bwd_packets":3,"fwd_bytes":54000,"bwd_bytes":180,"syn_count":40,"rst_count":0}'
```

## How the severity score works

`severity = 100 × attack_weight × (0.75 × P(attack) + 0.25 × anomaly_score)`
with weights DDoS 1.0, BruteForce 0.85, PortScan 0.70, Anomaly 0.55.
Levels: ≥85 Critical · ≥60 High · ≥35 Medium · else Low. Traffic the classifier calls benign but the Isolation
Forest finds highly unusual (anomaly score ≥ 0.8) is flagged as an `Anomaly`.

## Limitations (matches the synopsis assumptions)

Educational prototype, validated on public/simulated data - not a replacement for enterprise IDS/IPS. It
analyses flow-level features; it does not capture live packets.
