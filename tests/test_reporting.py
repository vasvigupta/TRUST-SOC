"""
Unit Tests for Evidence Report Generator (Milestone 3 — Stage 3.4)
==================================================================
Tests:
1. JSON evidence report creation and schema structure.
2. ReportLab PDF report generation and file validity.
3. MITRE ATT&CK mapping integration.
4. Database report registration.

Uses stdlib unittest and temporary test directories.
"""

import os
import json
import unittest
from pathlib import Path

from src.reporting.report_generator import ReportGenerator
from src.schemas.alert import create_empty_alert
from src.database.db import init_db
import src.config.config as conf_mod


class TestEvidenceReporting(unittest.TestCase):
    """Verifies JSON and ReportLab PDF report generation."""

    def setUp(self):
        self.test_reports_dir = conf_mod.ROOT_DIR / "data" / "test_reports"
        self.json_dir = self.test_reports_dir / "json"
        self.pdf_dir = self.test_reports_dir / "pdf"
        self.json_dir.mkdir(parents=True, exist_ok=True)
        self.pdf_dir.mkdir(parents=True, exist_ok=True)

        self.test_db_path = conf_mod.ROOT_DIR / "data" / "test_trust_soc_rep.db"
        self._cleanup()

        self.orig_db_path = conf_mod.DB_PATH
        conf_mod.DB_PATH = self.test_db_path
        init_db(self.test_db_path)

        self.generator = ReportGenerator(json_dir=self.json_dir, pdf_dir=self.pdf_dir)

    def tearDown(self):
        conf_mod.DB_PATH = self.orig_db_path
        self._cleanup()

    def _cleanup(self):
        db_dir = conf_mod.ROOT_DIR / "data"
        if db_dir.exists():
            for f in db_dir.glob("test_trust_soc_rep.db*"):
                try:
                    f.unlink()
                except Exception:
                    pass
        if self.test_reports_dir.exists():
            for p in self.test_reports_dir.rglob("*"):
                if p.is_file():
                    try:
                        p.unlink()
                    except Exception:
                        pass

    def _create_sample_alert(self):
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
        alert = create_empty_alert("test.csv", 42, meta, features, alert_id="alert-rep-test:42")
        alert["detection"] = {
            "model": "random_forest",
            "predicted_class": "DoS/DDoS",
            "probability": 0.98,
            "class_probabilities": {"DoS/DDoS": 0.98, "Benign": 0.02},
            "top_features": [
                {"rank": 1, "feature": "Flow Duration", "shap_value": 0.25, "feature_value": 2500000.0},
                {"rank": 2, "feature": "Flow Packets/s", "shap_value": 0.20, "feature_value": 4000.0},
            ],
            "is_alert": True,
        }
        alert["verification"] = {
            "decision": "CONFIRM",
            "p_v": 0.88,
            "signals": {
                "rule": {"score": 0.95, "strongly_contradictory": False, "details": {"matched_rules": ["Target port 80 matches DoS profile"]}},
                "statistical": {"score": 0.85, "strongly_contradictory": False, "details": {}},
                "behavioural": {"score": 0.80, "strongly_contradictory": False, "details": {}},
                "explanation": {"score": 0.90, "strongly_contradictory": False, "details": {}},
            },
            "rationale": "Strong multi-signal consensus corroborates attack: rule=0.95, statistical=0.85.",
        }
        alert["scoring"] = {
            "composite": 0.92,
            "band": "HIGH",
            "action": "AUTO_ESCALATE",
        }
        alert["audit_trail"] = [
            {"ts": "2026-10-26T10:00:00Z", "stage": "ingestion", "event": "Ingested flow"},
            {"ts": "2026-10-26T10:00:01Z", "stage": "detection", "event": "Classified DoS/DDoS (p=0.98)"},
            {"ts": "2026-10-26T10:00:02Z", "stage": "verification", "event": "Verified CONFIRM (p_v=0.88)"},
            {"ts": "2026-10-26T10:00:03Z", "stage": "scoring", "event": "Scored HIGH (C=0.92)"},
        ]
        return alert

    def test_json_report_generation(self):
        """JSON report is written with full canonical payload and MITRE ATT&CK context."""
        alert = self._create_sample_alert()
        json_path = self.generator.generate_json_report(alert)

        self.assertTrue(json_path.exists())
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("report_id", data)
        self.assertIn("mitre_attack", data)
        self.assertEqual(data["mitre_attack"]["technique_id"], "T1498")
        self.assertEqual(data["alert"]["alert_id"], "alert-rep-test:42")
        self.assertEqual(data["alert"]["scoring"]["band"], "HIGH")

    def test_pdf_report_generation(self):
        """ReportLab PDF is generated and produces a valid non-empty PDF document."""
        alert = self._create_sample_alert()
        pdf_path = self.generator.generate_pdf_report(alert)

        self.assertTrue(pdf_path.exists())
        file_size = os.path.getsize(pdf_path)
        self.assertGreater(file_size, 3000)

        with open(pdf_path, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-")

    def test_both_reports_generation_and_db_link(self):
        """generate_both_reports creates JSON, PDF, and registers metadata in SQLite."""
        alert = self._create_sample_alert()
        from src.database.alert_store import insert_alert, get_report_for_alert
        insert_alert(alert)

        res = self.generator.generate_both_reports(alert)
        self.assertIn("json_path", res)
        self.assertIn("pdf_path", res)
        self.assertTrue(Path(res["json_path"]).exists())
        self.assertTrue(Path(res["pdf_path"]).exists())

        rep = get_report_for_alert(alert["alert_id"])
        self.assertIsNotNone(rep)
        self.assertEqual(rep["alert_id"], alert["alert_id"])


if __name__ == "__main__":
    unittest.main()
