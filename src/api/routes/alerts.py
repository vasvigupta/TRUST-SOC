"""
FastAPI Route — /alerts
========================
GET  /alerts          — paginated list
GET  /alerts/summary  — per-class counts
GET  /alerts/{id}     — single alert
DELETE /alerts        — clear all (for dev/testing)
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from src.api.schemas import AlertOut, AlertListResponse, AlertSummaryResponse
from src.database.alert_store import (
    list_alerts, get_alert, count_alerts, alert_summary, clear_all
)

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/summary", response_model=AlertSummaryResponse,
            summary="Per-class alert counts")
def summary():
    return alert_summary()


@router.get("", response_model=AlertListResponse, summary="List all alerts (paginated)")
def get_alerts(
    skip:       int            = Query(0,    ge=0),
    limit:      int            = Query(50,   ge=1, le=200),
    prediction: Optional[str]  = Query(None, description="Filter by class"),
):
    alerts = list_alerts(skip=skip, limit=limit, prediction=prediction)
    total  = count_alerts(prediction=prediction)
    return AlertListResponse(
        total  = total,
        skip   = skip,
        limit  = limit,
        alerts = alerts,
    )


@router.get("/{alert_id}", response_model=AlertOut, summary="Get one alert by ID")
def get_one(alert_id: str):
    alert = get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


@router.delete("", summary="Clear all alerts (dev only)")
def delete_all():
    n = clear_all()
    return {"deleted": n}
