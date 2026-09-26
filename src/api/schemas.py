"""
FastAPI — Pydantic Schemas
===========================
Request and response models for all API endpoints.
"""

from typing import Optional
from pydantic import BaseModel


# ── Detection ─────────────────────────────────────────────────────

class DetectRequest(BaseModel):
    """One network-flow record submitted for detection."""
    features: dict[str, float]   # { "Flow Duration": 1234.5, ... }


class TopFeature(BaseModel):
    feature:    str
    shap_value: Optional[float] = None
    importance: Optional[float] = None


class DetectResponse(BaseModel):
    alert_id:             str
    timestamp:            str
    prediction:           str
    probability:          float
    class_probabilities:  dict[str, float]
    top_features:         list[TopFeature]
    status:               str
    verification_result:  str


# ── Alerts ────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id:                   int
    alert_id:             str
    timestamp:            str
    flow_index:           Optional[int]
    prediction:           str
    probability:          float
    true_label:           Optional[str]
    status:               str
    top_features:         list
    class_probabilities:  dict
    verification_result:  str
    created_at:           str


class AlertListResponse(BaseModel):
    total:  int
    skip:   int
    limit:  int
    alerts: list[AlertOut]


class AlertSummaryResponse(BaseModel):
    total:    int
    by_class: dict[str, int]


# ── Replay ────────────────────────────────────────────────────────

class ReplayResponse(BaseModel):
    processed:  int
    stored:     int
    alerts:     list[DetectResponse]


# ── Metrics ───────────────────────────────────────────────────────

class MetricsResponse(BaseModel):
    model:               str
    accuracy:            float
    precision_weighted:  float
    recall_weighted:     float
    f1_weighted:         float
    fpr_macro:           float
    fpr_weighted:        float
    fpr_per_class:       dict[str, float]
    per_class_metrics:   dict[str, dict]
    note_fpr:            str
