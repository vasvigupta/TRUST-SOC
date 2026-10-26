"""
Alert Store & Persistence Operations (SQLite)
=============================================
Provides clean CRUD operations for alerts, reports, and audit trails.
Used by the log replay stream, report generators, and FastAPI backend endpoints.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from src.database.db import get_connection

log = logging.getLogger("TRUST-SOC.alert_store")


def insert_alert(alert: Dict[str, Any]) -> str:
    """
    Persists a Canonical Alert dictionary into SQLite.
    Inserts both the structured columns and the full raw_json string.
    Also persists individual audit trail events into the audit_events table.
    """
    alert_id = alert["alert_id"]
    flow = alert.get("flow", {})
    fields = flow.get("fields_available", {})
    det = alert.get("detection", {})
    ver = alert.get("verification", {})
    sc = alert.get("scoring", {})

    status = alert.get("status", "NEW")
    if ver.get("decision") == "REJECT":
        status = "FALSE_POSITIVE"

    raw_json_str = json.dumps(alert, ensure_ascii=False)

    sql_alert = """
    INSERT OR REPLACE INTO alerts (
        alert_id, timestamp, source_file, row_index,
        src_ip, dst_ip, src_port, dst_port, protocol,
        predicted_class, detection_probability,
        verification_decision, verification_pv,
        composite_confidence, confidence_band,
        status, raw_json
    ) VALUES (
        :alert_id, :timestamp, :source_file, :row_index,
        :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
        :predicted_class, :detection_probability,
        :verification_decision, :verification_pv,
        :composite_confidence, :confidence_band,
        :status, :raw_json
    );
    """

    params = {
        "alert_id": alert_id,
        "timestamp": alert.get("ingested_at", datetime.now(timezone.utc).isoformat()),
        "source_file": flow.get("source_file", ""),
        "row_index": flow.get("row_index", 0),
        "src_ip": str(fields.get("Source IP", "")),
        "dst_ip": str(fields.get("Destination IP", "")),
        "src_port": int(fields.get("Source Port", 0)),
        "dst_port": int(fields.get("Destination Port", 0)),
        "protocol": int(fields.get("Protocol", 0)),
        "predicted_class": det.get("predicted_class", "Benign"),
        "detection_probability": float(det.get("probability", 0.0)),
        "verification_decision": ver.get("decision", "NOT_IMPLEMENTED"),
        "verification_pv": float(ver.get("p_v", 0.0)),
        "composite_confidence": float(sc.get("composite", 0.0)),
        "confidence_band": sc.get("band", "LOW"),
        "status": status,
        "raw_json": raw_json_str,
    }

    with get_connection() as conn:
        conn.execute(sql_alert, params)

        # Insert audit trail events
        audit_trail = alert.get("audit_trail", [])
        if audit_trail:
            sql_audit = """
            INSERT INTO audit_events (alert_id, timestamp, stage, event)
            VALUES (?, ?, ?, ?);
            """
            audit_rows = [
                (alert_id, item.get("ts", ""), item.get("stage", ""), item.get("event", ""))
                for item in audit_trail
            ]
            conn.executemany(sql_audit, audit_rows)

    return alert_id


def get_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    """Fetches full canonical alert dictionary by alert_id."""
    sql = "SELECT raw_json, status FROM alerts WHERE alert_id = ?;"
    with get_connection() as conn:
        row = conn.execute(sql, (alert_id,)).fetchone()
        if not row:
            return None
        alert = json.loads(row["raw_json"])
        alert["status"] = row["status"]
        return alert


def list_alerts(
    skip: int = 0,
    limit: int = 50,
    band: Optional[str] = None,
    decision: Optional[str] = None,
    status: Optional[str] = None,
    predicted_class: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Returns paginated list of alerts with optional multi-attribute filtering."""
    sql = """
    SELECT alert_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
           predicted_class, detection_probability, verification_decision,
           verification_pv, composite_confidence, confidence_band, status, created_at
    FROM alerts
    WHERE 1=1
    """
    args = []

    if band:
        sql += " AND confidence_band = ?"
        args.append(band.upper())
    if decision:
        sql += " AND verification_decision = ?"
        args.append(decision.upper())
    if status:
        sql += " AND status = ?"
        args.append(status.upper())
    if predicted_class:
        sql += " AND predicted_class = ?"
        args.append(predicted_class)

    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?;"
    args.extend([limit, skip])

    with get_connection() as conn:
        rows = conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]


def update_alert_status(alert_id: str, new_status: str) -> bool:
    """Updates the triage status of an alert and appends an audit event."""
    valid_statuses = {"NEW", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"}
    norm_status = new_status.upper().strip()
    if norm_status not in valid_statuses:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {valid_statuses}")

    now_iso = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        row = conn.execute("SELECT raw_json FROM alerts WHERE alert_id = ?;", (alert_id,)).fetchone()
        if not row:
            return False

        alert = json.loads(row["raw_json"])
        alert["status"] = norm_status
        if "audit_trail" not in alert or not isinstance(alert["audit_trail"], list):
            alert["audit_trail"] = []

        event_text = f"Analyst updated status to {norm_status}"
        alert["audit_trail"].append({
            "ts": now_iso,
            "stage": "triage_action",
            "event": event_text,
        })
        updated_json = json.dumps(alert, ensure_ascii=False)

        conn.execute(
            "UPDATE alerts SET status = ?, raw_json = ? WHERE alert_id = ?;",
            (norm_status, updated_json, alert_id),
        )
        conn.execute(
            "INSERT INTO audit_events (alert_id, timestamp, stage, event) VALUES (?, ?, ?, ?);",
            (alert_id, now_iso, "triage_action", event_text),
        )

    return True


def insert_report(
    report_id: str,
    alert_id: str,
    json_path: str,
    pdf_path: str,
    summary: str = "",
) -> str:
    """Inserts a generated report record."""
    now_iso = datetime.now(timezone.utc).isoformat()
    sql = """
    INSERT OR REPLACE INTO reports (report_id, alert_id, generated_at, json_path, pdf_path, summary)
    VALUES (?, ?, ?, ?, ?, ?);
    """
    with get_connection() as conn:
        conn.execute(sql, (report_id, alert_id, now_iso, str(json_path), str(pdf_path), summary))
    return report_id


def get_report_for_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves generated report metadata for an alert."""
    sql = "SELECT * FROM reports WHERE alert_id = ? ORDER BY generated_at DESC LIMIT 1;"
    with get_connection() as conn:
        row = conn.execute(sql, (alert_id,)).fetchone()
        return dict(row) if row else None


def get_db_stats() -> Dict[str, Any]:
    """Returns dashboard-level operational statistics."""
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) as c FROM alerts;").fetchone()["c"]

        bands = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in conn.execute("SELECT confidence_band, COUNT(*) as c FROM alerts GROUP BY confidence_band;"):
            bands[r["confidence_band"]] = r["c"]

        decisions = {"CONFIRM": 0, "REDUCE": 0, "REJECT": 0}
        for r in conn.execute("SELECT verification_decision, COUNT(*) as c FROM alerts GROUP BY verification_decision;"):
            if r["verification_decision"] in decisions:
                decisions[r["verification_decision"]] = r["c"]

        statuses = {"NEW": 0, "ACKNOWLEDGED": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0}
        for r in conn.execute("SELECT status, COUNT(*) as c FROM alerts GROUP BY status;"):
            if r["status"] in statuses:
                statuses[r["status"]] = r["c"]

        classes = {}
        for r in conn.execute("SELECT predicted_class, COUNT(*) as c FROM alerts GROUP BY predicted_class;"):
            classes[r["predicted_class"]] = r["c"]

    return {
        "total_alerts": total,
        "by_band": bands,
        "by_decision": decisions,
        "by_status": statuses,
        "by_class": classes,
    }
