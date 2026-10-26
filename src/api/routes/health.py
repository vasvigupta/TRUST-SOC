"""
Health Route — System & Model Status
====================================
"""

import sys
from pathlib import Path
from fastapi import APIRouter
from src.config.config import MODEL_PATH, XGB_MODEL_PATH, IF_MODEL_PATH, DB_PATH, API_PORT
from src.database.db import get_connection
from src.api.schemas import HealthResponse

router = APIRouter(prefix="/api", tags=["System"])


@router.get("/health", response_model=HealthResponse, summary="System health & model status")
def get_health():
    db_ok = False
    try:
        with get_connection() as conn:
            conn.execute("SELECT 1;").fetchone()
            db_ok = True
    except Exception:
        db_ok = False

    return HealthResponse(
        service="TRUST-SOC Detection & Verification Pipeline API",
        version="1.0.0",
        status="running",
        models_loaded={
            "rf_detection_agent": MODEL_PATH.exists(),
            "xgb_detection_agent": XGB_MODEL_PATH.exists(),
            "isolation_forest": IF_MODEL_PATH.exists(),
        },
        database_connected=db_ok,
        docs=f"http://localhost:{API_PORT}/docs",
    )
