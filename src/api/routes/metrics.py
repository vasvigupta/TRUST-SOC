"""
FastAPI Route — /metrics
=========================
GET /metrics  — returns saved baseline detection metrics
GET /replay   — trigger N-record log replay, store alerts, return results
"""

import json
import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from src.api.schemas import MetricsResponse, ReplayResponse, DetectResponse, TopFeature
from src.config.config import METRICS_DIR

router = APIRouter(tags=["Metrics & Replay"])


@router.get("/metrics", response_model=MetricsResponse,
            summary="Detection Agent baseline metrics")
def get_metrics():
    path = METRICS_DIR / "detection_baseline.json"
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail="Metrics not found. Run: python run.py --stage evaluate"
        )
    return json.loads(path.read_text())


@router.get("/replay", response_model=ReplayResponse,
            summary="Replay N historical flows through detection pipeline")
def replay(n: int = Query(20, ge=1, le=200, description="Number of flows to replay")):
    """
    Replays n records from the sample CSV.
    Each alert is stored in SQLite.
    SHAP is disabled for speed during replay.
    """
    from src.detection.model import DetectionAgent
    from src.ingestion.log_replay import LogReplayEngine
    from src.database.alert_store import insert_many
    from src.config.config import REPLAY_SAMPLE_PATH

    try:
        agent  = DetectionAgent.load()
        engine = LogReplayEngine(agent, use_shap=False)
        engine.load()
        engine.start()
        raw_alerts = engine.replay_n(n)
        engine.stop()
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))

    stored = insert_many(raw_alerts)

    response_alerts = [
        DetectResponse(
            alert_id            = a["alert_id"],
            timestamp           = a["timestamp"],
            prediction          = a["prediction"],
            probability         = a["probability"],
            class_probabilities = a.get("class_probabilities", {}),
            top_features        = [TopFeature(**f) for f in a.get("top_features", [])],
            status              = a.get("status", "DETECTED"),
            verification_result = a.get("verification_result", "NOT_IMPLEMENTED"),
        )
        for a in raw_alerts
    ]

    return ReplayResponse(
        processed = len(raw_alerts),
        stored    = stored,
        alerts    = response_alerts,
    )
