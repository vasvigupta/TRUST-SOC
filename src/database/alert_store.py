"""
Alert Store — CRUD Operations (SQLite)
========================================
All alert persistence logic is here.
FastAPI routes import these functions directly.
"""

import json
import sqlite3
from typing import Optional
from src.database.db import get_connection


# ── helpers ──────────────────────────────────────────────────────

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for field in ("top_features", "class_probabilities"):
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
    return d


# ── write ─────────────────────────────────────────────────────────

def insert_alert(alert: dict) -> int:
    """
    Persist one alert dict to SQLite.
    Returns the new row id.
    Silently ignores duplicate alert_ids (IGNORE on conflict).
    """
    sql = """
    INSERT OR IGNORE INTO alerts
        (alert_id, timestamp, flow_index, prediction, probability,
         true_label, status, top_features, class_probabilities,
         verification_result)
    VALUES
        (:alert_id, :timestamp, :flow_index, :prediction, :probability,
         :true_label, :status, :top_features, :class_probabilities,
         :verification_result)
    """
    params = {
        "alert_id":            alert.get("alert_id"),
        "timestamp":           alert.get("timestamp"),
        "flow_index":          alert.get("flow_index"),
        "prediction":          alert.get("prediction"),
        "probability":         alert.get("probability"),
        "true_label":          alert.get("true_label"),
        "status":              alert.get("status", "DETECTED"),
        "top_features":        json.dumps(alert.get("top_features", [])),
        "class_probabilities": json.dumps(alert.get("class_probabilities", {})),
        "verification_result": alert.get("verification_result", "NOT_IMPLEMENTED"),
    }
    with get_connection() as conn:
        cur = conn.execute(sql, params)
        return cur.lastrowid


def insert_many(alerts: list[dict]) -> int:
    """Bulk insert a list of alerts. Returns number inserted."""
    return sum(1 for a in alerts if insert_alert(a))


# ── read ──────────────────────────────────────────────────────────

def get_alert(alert_id: str) -> Optional[dict]:
    """Fetch one alert by alert_id."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def list_alerts(
    skip: int = 0,
    limit: int = 50,
    prediction: Optional[str] = None,
) -> list[dict]:
    """Return paginated alerts, optionally filtered by prediction class."""
    sql  = "SELECT * FROM alerts"
    args = []
    if prediction:
        sql += " WHERE prediction = ?"
        args.append(prediction)
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args += [limit, skip]

    with get_connection() as conn:
        rows = conn.execute(sql, args).fetchall()
    return [_row_to_dict(r) for r in rows]


def count_alerts(prediction: Optional[str] = None) -> int:
    sql  = "SELECT COUNT(*) FROM alerts"
    args = []
    if prediction:
        sql += " WHERE prediction = ?"
        args.append(prediction)
    with get_connection() as conn:
        return conn.execute(sql, args).fetchone()[0]


def alert_summary() -> dict:
    """Per-class counts + total."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT prediction, COUNT(*) as cnt FROM alerts GROUP BY prediction"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return {
        "total": total,
        "by_class": {r["prediction"]: r["cnt"] for r in rows},
    }


def clear_all() -> int:
    """Delete all alerts. Returns rows deleted."""
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM alerts")
        return cur.rowcount
