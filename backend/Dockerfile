FROM python:3.12-slim
WORKDIR /srv
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY threatdetect threatdetect
COPY scripts scripts
COPY backend backend
# Train a quick-start model at build time if none was shipped (uses synthetic data).
COPY models models
RUN [ -f models/detector.joblib ] || python scripts/train.py --synthetic
EXPOSE 8000
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
