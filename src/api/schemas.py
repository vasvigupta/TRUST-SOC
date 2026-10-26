"""
Pydantic Schemas for TRUST-SOC FastAPI Backend (Milestone 4)
============================================================
Defines request and response schemas matching Section 5 Canonical Alert
and Section 13 API specifications.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    service: str = "TRUST-SOC API"
    version: str = "1.0.0"
    status: str = "running"
    models_loaded: Dict[str, bool]
    database_connected: bool
    docs: str


class FPRReductionSummary(BaseModel):
    baseline_fpr_pct: float
    post_verification_lenient_fpr_pct: float
    relative_reduction_pct: float
    absolute_reduction_pct_pts: float
    recall_cost_pct: float
    cohens_kappa: float


class StatsResponse(BaseModel):
    total_alerts: int
    by_band: Dict[str, int]
    by_decision: Dict[str, int]
    by_status: Dict[str, int]
    by_class: Dict[str, int]
    fpr_reduction: FPRReductionSummary


class AlertListItem(BaseModel):
    alert_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    predicted_class: str
    detection_probability: float
    verification_decision: str
    verification_pv: float
    composite_confidence: float
    confidence_band: str
    status: str
    created_at: str


class AlertListResponse(BaseModel):
    total: int
    skip: int
    limit: int
    alerts: List[AlertListItem]


class StatusUpdateRequest(BaseModel):
    status: str = Field(..., description="NEW, ACKNOWLEDGED, RESOLVED, or FALSE_POSITIVE")
    note: Optional[str] = None


class StatusUpdateResponse(BaseModel):
    success: bool
    alert_id: str
    status: str
    updated_at: str


class ReplayControlRequest(BaseModel):
    action: str = Field(..., description="'start', 'pause', 'resume', 'step', or 'set_rate'")
    rate: Optional[float] = Field(None, description="Playback rate in records/sec")
    n: Optional[int] = Field(1, description="Number of steps for 'step' action")


class ReplayStatusResponse(BaseModel):
    is_running: bool
    is_paused: bool
    rate: float
    current_index: int
    total_records: int
    queue_depth: int


class DetectRequest(BaseModel):
    features: Dict[str, float]
    metadata: Optional[Dict[str, Any]] = None


class DetectResponse(BaseModel):
    alert_id: str
    timestamp: str
    prediction: str
    probability: float
    verification_decision: str
    verification_pv: float
    composite_confidence: float
    confidence_band: str
    rationale: str
    signals: Dict[str, Any]
    top_features: List[Dict[str, Any]]
    class_probabilities: Dict[str, float]
    pdf_report_url: str
    json_report_url: str

