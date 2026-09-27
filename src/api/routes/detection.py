"""
FastAPI Route — /detect
========================
POST /detect
  Body: { "features": { "Flow Duration": 1234, ... } }
  Returns: full alert with prediction, confidence, SHAP
"""

import datetime
import uuid
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from src.api.schemas import DetectRequest, DetectResponse, TopFeature
from src.database.alert_store import insert_alert

router = APIRouter(prefix="/detect", tags=["Detection"])

# ── Lazy model cache ──────────────────────────────────────────────
_agent = None

def _get_agent():
    global _agent
    if _agent is None:
        from src.detection.model import DetectionAgent
        _agent = DetectionAgent.load()
    return _agent


@router.post("", response_model=DetectResponse, summary="Detect attack class for one flow")
def detect(req: DetectRequest):
    """
    Submit a network-flow feature dict and receive:
    - predicted class
    - confidence probability
    - per-class probabilities
    - SHAP top-feature attributions
    - alert persisted to SQLite
    """
    agent = _get_agent()

    import pandas as pd
    import numpy as np

    # Build feature row in the correct column order
    try:
        feature_row = pd.Series(req.features).reindex(agent.feature_names).fillna(0.0)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Feature mismatch: {e}")

    # Detection
    result = agent.predict_single(feature_row)

    # SHAP explanation
    top_features = []
    try:
        from src.explainability.shap_explainer import explain_single_prediction
        expl = explain_single_prediction(agent, feature_row, list(agent.encoder.classes_))
        top_features = [TopFeature(**f) for f in expl["top_features"]]
    except Exception:
        pass   # SHAP is optional — detection still works

    alert_id  = f"ALERT-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    alert_dict = {
        "alert_id":            alert_id,
        "timestamp":           timestamp,
        "flow_index":          None,
        "prediction":          result["prediction"],
        "probability":         result["confidence"],
        "true_label":          None,
        "status":              "DETECTED",
        "top_features":        [f.model_dump() for f in top_features],
        "class_probabilities": result["class_probabilities"],
        "verification_result": "NOT_IMPLEMENTED",
    }
    insert_alert(alert_dict)

    return DetectResponse(
        alert_id            = alert_id,
        timestamp           = timestamp,
        prediction          = result["prediction"],
        probability         = result["confidence"],
        class_probabilities = result["class_probabilities"],
        top_features        = top_features,
        status              = "DETECTED",
        verification_result = "NOT_IMPLEMENTED",
    )


@router.get("/examples", summary="Get pre-configured example flow records for each class")
def get_examples():
    import json
    from src.config.config import SAMPLE_DIR
    examples_file = SAMPLE_DIR / "neutral_example_flows.json"
    if not examples_file.exists():
        examples_file = SAMPLE_DIR / "example_flows.json"
    if examples_file.exists():
        return json.loads(examples_file.read_text())
    return {}


