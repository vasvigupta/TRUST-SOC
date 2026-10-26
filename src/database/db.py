"""
SQLite Database Initialisation & Connection Management
======================================================
Manages relational storage for TRUST-SOC:
  - alerts: Structured alert metadata + full canonical raw_json payload
  - reports: Generated JSON & PDF report paths and summaries
  - audit_events: Fine-grained audit trail events

Strictly adheres to Section 6 and locked technology stack (stdlib sqlite3 with WAL mode).
"""

import sqlite3
import logging
from pathlib import Path
from src.config.config import DB_PATH

log = logging.getLogger("TRUST-SOC.database")

DDL_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id              TEXT PRIMARY KEY,
    timestamp             TEXT NOT NULL,
    source_file           TEXT,
    row_index             INTEGER,
    src_ip                TEXT,
    dst_ip                TEXT,
    src_port              INTEGER,
    dst_port              INTEGER,
    protocol              INTEGER,
    predicted_class       TEXT NOT NULL,
    detection_probability REAL NOT NULL,
    verification_decision TEXT NOT NULL,
    verification_pv       REAL NOT NULL,
    composite_confidence  REAL NOT NULL,
    confidence_band       TEXT NOT NULL,
    status                TEXT DEFAULT 'NEW',
    raw_json              TEXT NOT NULL,
    created_at            TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_pred   ON alerts(predicted_class);
CREATE INDEX IF NOT EXISTS idx_alerts_band   ON alerts(confidence_band);
CREATE INDEX IF NOT EXISTS idx_alerts_dec    ON alerts(verification_decision);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_ts     ON alerts(timestamp);
"""

DDL_REPORTS = """
CREATE TABLE IF NOT EXISTS reports (
    report_id    TEXT PRIMARY KEY,
    alert_id     TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    json_path    TEXT NOT NULL,
    pdf_path     TEXT NOT NULL,
    summary      TEXT,
    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reports_alert ON reports(alert_id);
"""

DDL_AUDIT = """
CREATE TABLE IF NOT EXISTS audit_events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   TEXT NOT NULL,
    timestamp  TEXT NOT NULL,
    stage      TEXT NOT NULL,
    event      TEXT NOT NULL,
    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_audit_alert ON audit_events(alert_id);
"""


def get_connection(db_path: Path = None) -> sqlite3.Connection:
    """
    Opens an SQLite connection with WAL mode and row_factory enabled.
    Safe for multi-threaded FastAPI concurrency.
    """
    if db_path is None:
        from src.config.config import DB_PATH
        db_path = DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(db_path: Path = None):
    """
    Initializes database schema idempotently.
    Migrates legacy schemas if needed.
    """
    if db_path is None:
        from src.config.config import DB_PATH
        db_path = DB_PATH
    log.info(f"Initializing SQLite database schema at {db_path}...")
    with get_connection(db_path) as conn:
        # Check if legacy alerts table exists without predicted_class column
        cols = [c[1] for c in conn.execute("PRAGMA table_info(alerts);").fetchall()]
        if cols and "predicted_class" not in cols:
            log.warning("Detected legacy alerts table schema; migrating to Milestone 3 canonical schema...")
            conn.execute("DROP TABLE IF EXISTS alerts;")

        conn.executescript(DDL_ALERTS)
        conn.executescript(DDL_REPORTS)
        conn.executescript(DDL_AUDIT)
    log.info("Database schema initialized successfully.")
