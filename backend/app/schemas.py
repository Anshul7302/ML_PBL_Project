from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class FlowIn(BaseModel):
    """A network flow described by the features the model was trained on."""
    protocol: int = Field(6, ge=0, le=255, description="IP protocol number (6=TCP, 17=UDP)")
    src_port: int = Field(0, ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    duration_ms: float = Field(..., ge=0)
    fwd_packets: float = Field(..., ge=0)
    bwd_packets: float = Field(0, ge=0)
    fwd_bytes: float = Field(..., ge=0)
    bwd_bytes: float = Field(0, ge=0)
    syn_count: float = Field(0, ge=0)
    rst_count: float = Field(0, ge=0)
    src_ip: str | None = None
    dst_ip: str | None = None

    model_config = ConfigDict(json_schema_extra={"example": {
        "protocol": 6, "src_port": 51544, "dst_port": 80, "duration_ms": 40,
        "fwd_packets": 900, "bwd_packets": 3, "fwd_bytes": 54000, "bwd_bytes": 180,
        "syn_count": 40, "rst_count": 0, "src_ip": "185.10.4.9", "dst_ip": "10.0.1.20"}})


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    src_ip: str | None
    dst_ip: str | None
    protocol: int
    src_port: int
    dst_port: int
    status: str
    attack_type: str
    confidence: float
    anomaly_score: float
    severity_score: float
    severity_level: str
    probabilities: dict
    features: dict


class SimulateIn(BaseModel):
    count: int = Field(20, ge=1, le=500)
    attack_ratio: float = Field(0.3, ge=0.0, le=1.0, description="share of generated flows that are attacks")


class SimulateOut(BaseModel):
    generated: int
    suspicious: int
    detections: list[DetectionOut]
