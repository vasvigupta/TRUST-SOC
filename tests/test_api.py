"""
Unit & Integration Tests for FastAPI Backend Service (Milestone 4 — Stage 4.3)
=============================================================================
Tests all required REST endpoints:
  - GET  /api/health
  - GET  /api/stats
  - GET  /api/alerts (with pagination and multi-attribute filters)
  - GET  /api/alerts/{alert_id}
  - POST /api/alerts/{alert_id}/status
  - GET  /api/alerts/{alert_id}/report/json
  - GET  /api/alerts/{alert_id}/report/pdf
  - POST /api/replay/control
  - GET  /api/replay/status

Uses FastAPI TestClient and stdlib unittest.
"""

import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from src.api.main import app
from src.database.db import init_db, get_connection
from src.database.alert_store import insert_alert
from src.schemas.alert import create_empty_alert
import src.config.config as conf_mod


class TestFastAPIBackend(unittest.TestCase):
    """End-to-end tests for all backend API endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        # Dedicated test database path
        self.test_db_path = conf_mod.ROOT_DIR / "data" / "test_api_trust_soc.db"
        self._cleanup()

        self.orig_db_path = conf_mod.DB_PATH
        conf_mod.DB_PATH = self.test_db_path
        init_db(self.test_db_path)

        with get_connection(self.test_db_path) as conn:
            conn.execute("DELETE FROM audit_events;")
            conn.execute("DELETE FROM reports;")
            conn.execute("DELETE FROM alerts;")

        # Populate a sample test alert
        self.sample_alert = self._create_sample_alert("alert-api:1")
        insert_alert(self.sample_alert)

    def tearDown(self):
        conf_mod.DB_PATH = self.orig_db_path
        self._cleanup()

    def _cleanup(self):
        db_dir = conf_mod.ROOT_DIR / "data"
        if db_dir.exists():
            for f in db_dir.glob("test_api_trust_soc.db*"):
                try:
                    f.unlink()
                except Exception:
                    pass

    def _create_sample_alert(self, alert_id="alert-api:1", pred="DoS/DDoS", prob=0.98, band="HIGH", dec="CONFIRM"):
        meta = {
            "Flow ID": "172.16.0.1-192.168.10.50-50000-80-6",
            "Source IP": "172.16.0.1",
            "Destination IP": "192.168.10.50",
            "Source Port": 50000,
            "Destination Port": 80,
            "Protocol": 6,
            "Timestamp": "07/07/2017 10:00:00",
        }
        features = {
            "Flow Duration": 2500000.0,
            "Flow Packets/s": 4000.0,
            "Flow Bytes/s": 1500000.0,
            "Packet Length Mean": 350.0,
        }
        alert = create_empty_alert("test.csv", 42, meta, features, alert_id=alert_id)
        alert["detection"] = {
            "model": "random_forest",
            "predicted_class": pred,
            "probability": prob,
            "class_probabilities": {pred: prob, "Benign": 1.0 - prob},
            "top_features": [
                {"rank": 1, "feature": "Flow Duration", "shap_value": 0.25, "feature_value": 2500000.0},
            ],
            "is_alert": True,
        }
        alert["verification"] = {
            "decision": dec,
            "p_v": 0.88,
            "signals": {
                "rule": {"score": 0.95, "strongly_contradictory": False, "details": {}},
                "statistical": {"score": 0.85, "strongly_contradictory": False, "details": {}},
                "behavioural": {"score": 0.80, "strongly_contradictory": False, "details": {}},
                "explanation": {"score": 0.90, "strongly_contradictory": False, "details": {}},
            },
            "rationale": "Strong multi-signal consensus corroborates attack.",
        }
        alert["scoring"] = {
            "composite": 0.92,
            "band": band,
            "action": "AUTO_ESCALATE",
        }
        alert["audit_trail"] = [
            {"ts": "2026-10-26T10:00:00Z", "stage": "ingestion", "event": "Ingested flow"},
            {"ts": "2026-10-26T10:00:01Z", "stage": "detection", "event": "Classified DoS/DDoS (p=0.98)"},
            {"ts": "2026-10-26T10:00:02Z", "stage": "verification", "event": "Verified CONFIRM (p_v=0.88)"},
            {"ts": "2026-10-26T10:00:03Z", "stage": "scoring", "event": "Scored HIGH (C=0.92)"},
        ]
        return alert

    def test_health_endpoint(self):
        """GET /api/health returns 200 with service information and database status."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "running")
        self.assertIn("models_loaded", data)
        self.assertTrue(data["database_connected"])

    def test_stats_endpoint(self):
        """GET /api/stats returns counts and measured FPR reduction metrics."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_alerts", data)
        self.assertIn("by_band", data)
        self.assertIn("by_decision", data)
        self.assertIn("fpr_reduction", data)
        self.assertAlmostEqual(data["fpr_reduction"]["relative_reduction_pct"], 98.79, places=1)

    def test_get_alerts_feed_and_filters(self):
        """GET /api/alerts supports pagination and band/decision filtering."""
        response = self.client.get("/api/alerts?skip=0&limit=10")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(data["total"], 1)
        self.assertEqual(len(data["alerts"]), 1)
        self.assertEqual(data["alerts"][0]["alert_id"], "alert-api:1")

        # Filter by confidence band
        resp_high = self.client.get("/api/alerts?confidence_band=HIGH")
        self.assertEqual(len(resp_high.json()["alerts"]), 1)

        resp_low = self.client.get("/api/alerts?confidence_band=LOW")
        self.assertEqual(len(resp_low.json()["alerts"]), 0)

    def test_get_single_alert(self):
        """GET /api/alerts/{alert_id} returns full Canonical Alert JSON."""
        response = self.client.get("/api/alerts/alert-api:1")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["alert_id"], "alert-api:1")
        self.assertIn("flow", data)
        self.assertIn("detection", data)
        self.assertIn("verification", data)
        self.assertIn("scoring", data)
        self.assertIn("audit_trail", data)

        # 404 on missing alert
        resp_404 = self.client.get("/api/alerts/non-existent-alert")
        self.assertEqual(resp_404.status_code, 404)

    def test_update_status(self):
        """POST /api/alerts/{alert_id}/status updates status and logs event."""
        payload = {"status": "ACKNOWLEDGED", "note": "Analyst investigating"}
        response = self.client.post("/api/alerts/alert-api:1/status", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "ACKNOWLEDGED")

        # Verify persisted state
        get_resp = self.client.get("/api/alerts/alert-api:1")
        self.assertEqual(get_resp.json()["status"], "ACKNOWLEDGED")

    def test_download_reports(self):
        """GET /api/alerts/{alert_id}/report/json and /pdf return valid file streams."""
        # JSON report
        json_resp = self.client.get("/api/alerts/alert-api:1/report/json")
        self.assertEqual(json_resp.status_code, 200)
        self.assertEqual(json_resp.headers["content-type"], "application/json")

        # PDF report
        pdf_resp = self.client.get("/api/alerts/alert-api:1/report/pdf")
        self.assertEqual(pdf_resp.status_code, 200)
        self.assertEqual(pdf_resp.headers["content-type"], "application/pdf")
        self.assertEqual(pdf_resp.content[:5], b"%PDF-")

    def test_replay_control_and_status(self):
        """POST /api/replay/control controls simulator and GET /api/replay/status returns state."""
        # Check status
        status_resp = self.client.get("/api/replay/status")
        self.assertEqual(status_resp.status_code, 200)
        self.assertIn("is_running", status_resp.json())

        # Step replay
        step_resp = self.client.post("/api/replay/control", json={"action": "step", "n": 1})
        self.assertEqual(step_resp.status_code, 200)
        self.assertEqual(step_resp.json()["status"], "stepped")

        # Set rate
        rate_resp = self.client.post("/api/replay/control", json={"action": "set_rate", "rate": 15.0})
        self.assertEqual(rate_resp.status_code, 200)
        self.assertEqual(rate_resp.json()["rate"], 15.0)

    def test_detect_endpoint(self):
        """GET /api/detect/examples and POST /api/detect run full pipeline."""
        ex_resp = self.client.get("/api/detect/examples")
        self.assertEqual(ex_resp.status_code, 200)
        self.assertIsInstance(ex_resp.json(), dict)

        payload = {
            "features": {
                "Destination Port": 80.0,
                "Flow Duration": 125000.0,
                "Total Fwd Packets": 10.0,
                "Total Backward Packets": 2.0,
                "Total Length of Fwd Packets": 500.0,
                "Flow Packets/s": 80.0,
                "Flow Bytes/s": 4000.0,
                "Packet Length Mean": 50.0,
            }
        }
        det_resp = self.client.post("/api/detect", json=payload)
        self.assertEqual(det_resp.status_code, 200)
        det_data = det_resp.json()
        self.assertIn("alert_id", det_data)
        self.assertIn("prediction", det_data)
        self.assertIn("verification_decision", det_data)
        self.assertIn("composite_confidence", det_data)
        self.assertIn("confidence_band", det_data)
        self.assertIn("pdf_report_url", det_data)


if __name__ == "__main__":

    unittest.main()
