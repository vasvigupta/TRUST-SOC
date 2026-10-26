"""
Unit Tests for SQLite Storage Layer (Milestone 3 — Stage 3.3)
=============================================================
Tests:
1. Database schema initialization idempotency.
2. Alert insertion and retrieval.
3. Filtering and pagination in list_alerts.
4. Status update and audit logging.
5. Report metadata insertion and query.
6. Aggregate stats query.

Uses stdlib unittest with an isolated test database.
"""

import unittest
from pathlib import Path

from src.database.db import init_db, get_connection
from src.database.alert_store import (
    insert_alert,
    get_alert,
    list_alerts,
    update_alert_status,
    insert_report,
    get_report_for_alert,
    get_db_stats,
)
from src.schemas.alert import create_empty_alert
import src.config.config as conf_mod


class TestDatabaseOperations(unittest.TestCase):
    """Verifies SQLite storage layer operations."""

    def setUp(self):
        self.test_db_path = conf_mod.ROOT_DIR / "data" / "test_trust_soc.db"
        self._cleanup_test_db()

        self.orig_db_path = conf_mod.DB_PATH
        conf_mod.DB_PATH = self.test_db_path

        init_db(self.test_db_path)
        with get_connection(self.test_db_path) as conn:
            conn.execute("DELETE FROM audit_events;")
            conn.execute("DELETE FROM reports;")
            conn.execute("DELETE FROM alerts;")

    def tearDown(self):
        conf_mod.DB_PATH = self.orig_db_path
        self._cleanup_test_db()

    def _cleanup_test_db(self):
        db_dir = conf_mod.ROOT_DIR / "data"
        if db_dir.exists():
            for f in db_dir.glob("test_trust_soc.db*"):
                try:
                    f.unlink()
                except Exception:
                    pass

    def _create_sample_alert(self, alert_id="alert-test:1", pred="DoS/DDoS", prob=0.95, band="HIGH", dec="CONFIRM"):
        meta = {
            "Source IP": "172.16.0.1",
            "Destination IP": "192.168.10.50",
            "Source Port": 50000,
            "Destination Port": 80,
            "Protocol": 6,
        }
        features = {"Flow Duration": 1000000, "Flow Packets/s": 5000}
        alert = create_empty_alert("test.csv", 1, meta, features, alert_id=alert_id)
        alert["detection"]["predicted_class"] = pred
        alert["detection"]["probability"] = prob
        alert["detection"]["is_alert"] = True
        alert["verification"]["decision"] = dec
        alert["verification"]["p_v"] = 0.85
        alert["scoring"]["composite"] = 0.90
        alert["scoring"]["band"] = band
        alert["scoring"]["action"] = "AUTO_ESCALATE"
        return alert

    def test_insert_and_get_alert(self):
        """Alert can be inserted and faithfully retrieved."""
        alert = self._create_sample_alert(alert_id="alert-alpha:100")
        aid = insert_alert(alert)
        self.assertEqual(aid, "alert-alpha:100")

        retrieved = get_alert("alert-alpha:100")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["alert_id"], "alert-alpha:100")
        self.assertEqual(retrieved["detection"]["predicted_class"], "DoS/DDoS")
        self.assertEqual(retrieved["verification"]["decision"], "CONFIRM")
        self.assertEqual(retrieved["scoring"]["band"], "HIGH")

    def test_list_alerts_with_filters(self):
        """list_alerts supports filtering by band, decision, and pagination."""
        a1 = self._create_sample_alert("alert-1", pred="DoS/DDoS", band="HIGH", dec="CONFIRM")
        a2 = self._create_sample_alert("alert-2", pred="Botnet", band="MEDIUM", dec="REDUCE")
        a3 = self._create_sample_alert("alert-3", pred="Web Attack", band="LOW", dec="REJECT")

        insert_alert(a1)
        insert_alert(a2)
        insert_alert(a3)

        # Filter by band
        high_alerts = list_alerts(band="HIGH")
        self.assertEqual(len(high_alerts), 1)
        self.assertEqual(high_alerts[0]["alert_id"], "alert-1")

        # Filter by decision
        rej_alerts = list_alerts(decision="REJECT")
        self.assertEqual(len(rej_alerts), 1)
        self.assertEqual(rej_alerts[0]["alert_id"], "alert-3")

        # Pagination
        all_alerts = list_alerts(limit=2)
        self.assertEqual(len(all_alerts), 2)

    def test_update_alert_status(self):
        """Status transition updates state and appends audit event."""
        alert = self._create_sample_alert("alert-status:1")
        insert_alert(alert)

        # Update to ACKNOWLEDGED
        success = update_alert_status("alert-status:1", "ACKNOWLEDGED")
        self.assertTrue(success)

        updated = get_alert("alert-status:1")
        self.assertEqual(updated["status"], "ACKNOWLEDGED")

        # Check audit trail recorded the change
        audit_events = updated.get("audit_trail", [])
        last_event = audit_events[-1]
        self.assertEqual(last_event["stage"], "triage_action")
        self.assertIn("ACKNOWLEDGED", last_event["event"])

    def test_report_insert_and_retrieval(self):
        """Report metadata is persisted and linked to the alert."""
        alert = self._create_sample_alert("alert-rep:1")
        insert_alert(alert)

        rid = insert_report(
            report_id="REP-alert-rep:1",
            alert_id="alert-rep:1",
            json_path="/path/to/report.json",
            pdf_path="/path/to/report.pdf",
            summary="Test summary",
        )
        self.assertEqual(rid, "REP-alert-rep:1")

        rep = get_report_for_alert("alert-rep:1")
        self.assertIsNotNone(rep)
        self.assertEqual(rep["report_id"], "REP-alert-rep:1")
        self.assertEqual(rep["json_path"], "/path/to/report.json")

    def test_db_stats_aggregation(self):
        """get_db_stats correctly aggregates counts."""
        a1 = self._create_sample_alert("alert-s1", pred="DoS/DDoS", band="HIGH", dec="CONFIRM")
        a2 = self._create_sample_alert("alert-s2", pred="DoS/DDoS", band="HIGH", dec="CONFIRM")
        a3 = self._create_sample_alert("alert-s3", pred="Botnet", band="LOW", dec="REJECT")

        insert_alert(a1)
        insert_alert(a2)
        insert_alert(a3)

        stats = get_db_stats()
        self.assertEqual(stats["total_alerts"], 3)
        self.assertEqual(stats["by_band"]["HIGH"], 2)
        self.assertEqual(stats["by_band"]["LOW"], 1)
        self.assertEqual(stats["by_decision"]["CONFIRM"], 2)
        self.assertEqual(stats["by_decision"]["REJECT"], 1)


if __name__ == "__main__":
    unittest.main()
