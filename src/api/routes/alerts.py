"""
Alerts Route — Feed, Drill-down, Triage Actions, and Evidence Reports
====================================================================
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from src.database.alert_store import (
    list_alerts,
    get_alert,
    update_alert_status,
    get_report_for_alert,
)
from src.database.db import get_connection
from src.reporting.report_generator import ReportGenerator
from src.api.schemas import (
    AlertListResponse,
    AlertListItem,
    StatusUpdateRequest,
    StatusUpdateResponse,
)

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])
report_generator = ReportGenerator()


@router.get("", response_model=AlertListResponse, summary="List and filter alerts")
def get_alerts_feed(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    confidence_band: Optional[str] = Query(None, description="HIGH, MEDIUM, or LOW"),
    verification_decision: Optional[str] = Query(None, description="CONFIRM, REDUCE, or REJECT"),
    attack_class: Optional[str] = Query(None, description="Attack classification"),
    status: Optional[str] = Query(None, description="NEW, ACKNOWLEDGED, RESOLVED, or FALSE_POSITIVE"),
    sort_by: Optional[str] = Query("created_at", description="Field to sort by"),
    order: Optional[str] = Query("desc", description="'asc' or 'desc'"),
):
    """Returns paginated, multi-attribute filterable alert stream for the SOC dashboard."""
    # Count matching query
    count_sql = "SELECT COUNT(*) as c FROM alerts WHERE 1=1"
    args = []

    if confidence_band:
        count_sql += " AND confidence_band = ?"
        args.append(confidence_band.upper())
    if verification_decision:
        count_sql += " AND verification_decision = ?"
        args.append(verification_decision.upper())
    if attack_class:
        count_sql += " AND predicted_class = ?"
        args.append(attack_class)
    if status:
        count_sql += " AND status = ?"
        args.append(status.upper())

    # Build select query
    valid_sort_cols = {
        "created_at": "created_at",
        "timestamp": "timestamp",
        "composite_confidence": "composite_confidence",
        "detection_probability": "detection_probability",
        "verification_pv": "verification_pv",
    }
    sort_col = valid_sort_cols.get(sort_by, "created_at")
    sort_dir = "ASC" if str(order).lower() == "asc" else "DESC"

    select_sql = f"""
    SELECT alert_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
           predicted_class, detection_probability, verification_decision,
           verification_pv, composite_confidence, confidence_band, status, created_at
    FROM alerts
    WHERE 1=1
    """
    if confidence_band:
        select_sql += " AND confidence_band = ?"
    if verification_decision:
        select_sql += " AND verification_decision = ?"
    if attack_class:
        select_sql += " AND predicted_class = ?"
    if status:
        select_sql += " AND status = ?"

    select_sql += f" ORDER BY {sort_col} {sort_dir} LIMIT ? OFFSET ?;"
    query_args = list(args) + [limit, skip]

    with get_connection() as conn:
        total = conn.execute(count_sql, args).fetchone()["c"]
        rows = conn.execute(select_sql, query_args).fetchall()
        alerts = [dict(r) for r in rows]

    return AlertListResponse(
        total=total,
        skip=skip,
        limit=limit,
        alerts=[AlertListItem(**a) for a in alerts],
    )


@router.get("/{alert_id}", summary="Get full Canonical Alert JSON")
def get_single_alert(alert_id: str):
    """Returns full Section 5 Canonical Alert payload with features, SHAP, and audit trail."""
    alert = get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


@router.post("/{alert_id}/status", response_model=StatusUpdateResponse, summary="Update triage status")
def update_status(alert_id: str, payload: StatusUpdateRequest):
    """Updates status ('NEW', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE') and appends audit event."""
    alert = get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    try:
        success = update_alert_status(alert_id, payload.status)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to update alert status.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    now_iso = datetime.now(timezone.utc).isoformat()
    return StatusUpdateResponse(
        success=True,
        alert_id=alert_id,
        status=payload.status.upper(),
        updated_at=now_iso,
    )


@router.get("/{alert_id}/report/json", summary="Download evidence JSON report")
def download_json_report(alert_id: str):
    """Generates or retrieves full evidence JSON report."""
    alert = get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    json_path = report_generator.generate_json_report(alert)
    return FileResponse(
        path=str(json_path),
        media_type="application/json",
        filename=f"TRUST-SOC_{alert_id.replace(':', '_')}.json",
    )


@router.get("/{alert_id}/report/pdf", summary="Download ReportLab PDF report")
def download_pdf_report(alert_id: str):
    """Generates or retrieves publication-quality ReportLab PDF report."""
    alert = get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    pdf_path = report_generator.generate_pdf_report(alert)
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"TRUST-SOC_{alert_id.replace(':', '_')}.pdf",
    )
