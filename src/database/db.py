"""
SQLite Database — Initialisation & Connection
=============================================
Creates the trust_soc.db file and the alerts table on first run.
Uses connection-per-request pattern (safe for FastAPI).
"""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.config.config import DB_PATH


DDL = """
CREATE TABLE IF NOT EXISTS alerts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id             TEXT    UNIQUE NOT NULL,
    timestamp            TEXT    NOT NULL,
    flow_index           INTEGER,
    prediction           TEXT    NOT NULL,
    probability          REAL    NOT NULL,
    true_label           TEXT,
    status               TEXT    DEFAULT 'DETECTED',
    top_features         TEXT,       -- JSON array string
    class_probabilities  TEXT,       -- JSON object string
    verification_result  TEXT    DEFAULT 'NOT_IMPLEMENTED',
    created_at           TEXT    DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_prediction ON alerts(prediction);
CREATE INDEX IF NOT EXISTS idx_alerts_created    ON alerts(created_at);
"""


def get_connection() -> sqlite3.Connection:
    """Open a new SQLite connection (caller must close or use as context manager)."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row          # dict-like rows
    conn.execute("PRAGMA journal_mode=WAL") # safe for concurrent reads
    return conn


def init_db():
    """Create tables if they don't exist. Called once at API startup."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.executescript(DDL)
    print(f"[DB] SQLite initialised -> {DB_PATH}")
