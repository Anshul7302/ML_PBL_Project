from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Detection(Base):
    """One analysed network flow and the model's verdict."""
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    protocol: Mapped[int] = mapped_column(Integer)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)

    status: Mapped[str] = mapped_column(String(12), index=True)          # normal | suspicious
    attack_type: Mapped[str] = mapped_column(String(20), index=True)     # BENIGN | DDoS | PortScan | BruteForce | Anomaly
    confidence: Mapped[float] = mapped_column(Float)
    anomaly_score: Mapped[float] = mapped_column(Float)
    severity_score: Mapped[float] = mapped_column(Float)
    severity_level: Mapped[str] = mapped_column(String(10), index=True)  # None | Low | Medium | High | Critical
    is_suspicious: Mapped[bool] = mapped_column(Boolean, index=True)

    features: Mapped[dict] = mapped_column(JSON)                         # full flow feature vector
    probabilities: Mapped[dict] = mapped_column(JSON)

    __table_args__ = (Index("ix_detections_created_susp", "created_at", "is_suspicious"),)
