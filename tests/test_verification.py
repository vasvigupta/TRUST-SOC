"""
Unit Tests for TRUST-SOC Verification Agent (Milestone 2)
=========================================================
Tests:
1. Common signal contract & bounds [0, 1] for all 4 signals.
2. Decision Table boundary conditions with synthetic vectors.
3. Deterministic rationale generation.
4. Behavioural baseline causal integrity (no future leak).
5. Ground-truth isolation (Verification Agent NEVER inspects ground truth).
6. Canonical Alert Schema compliance.

Uses ONLY stdlib unittest per project specifications.
"""

import unittest
import numpy as np

from src.verification.decision import compute_verification_decision
from src.verification.rule_signal import RuleContextVerifier
from src.verification.statistical_signal import StatisticalVerifier
from src.verification.behavioural_signal import BehaviouralVerifier
from src.verification.explanation_signal import ExplanationVerifier
from src.verification.verification_agent import VerificationAgent
from src.schemas.alert import create_empty_alert, validate_alert


class TestVerificationSignals(unittest.TestCase):
    """Tests signal bounds, contract compliance, and independence."""

    def setUp(self):
        self.rule_v = RuleContextVerifier()
        self.stat_v = StatisticalVerifier()
        self.behav_v = BehaviouralVerifier()
        self.expl_v = ExplanationVerifier()

    def test_rule_signal_contract_and_bounds(self):
        """Signal (a) must return float in [0, 1], bool strongly_contradictory, and details dict."""
        meta = {
            "Source IP": "172.16.0.1",
            "Destination IP": "192.168.10.50",
            "Source Port": 44444,
            "Destination Port": 80,
            "Protocol": 6,
        }
        features = {
            "Flow Duration": 1500000,
            "Flow Packets/s": 8000,
            "Packet Length Mean": 500,
        }
        res = self.rule_v.verify_flow("DoS/DDoS", meta, features)

        self.assertIn("score", res)
        self.assertIn("strongly_contradictory", res)
        self.assertIn("details", res)
        self.assertIsInstance(res["score"], float)
        self.assertIsInstance(res["strongly_contradictory"], bool)
        self.assertIsInstance(res["details"], dict)
        self.assertGreaterEqual(res["score"], 0.0)
        self.assertLessEqual(res["score"], 1.0)

    def test_rule_signal_whitelisted_dns_contradiction(self):
        """Whitelisted DNS queries must be flagged as strongly contradictory for attack alerts."""
        meta = {
            "Source IP": "192.168.10.15",
            "Destination IP": "192.168.10.3",
            "Source Port": 52341,
            "Destination Port": 53,
            "Protocol": 17,
        }
        features = {"Flow Duration": 200, "Flow Packets/s": 100, "Total Fwd Packets": 1}
        res = self.rule_v.verify_flow("Botnet", meta, features)
        self.assertTrue(res["strongly_contradictory"])
        self.assertLess(res["score"], 0.20)

    def test_statistical_signal_contract_and_bounds(self):
        """Signal (b) must return score in [0, 1] using independently trained Isolation Forest."""
        # Random normal vector representing standardized flow features
        vec = np.zeros(68, dtype=np.float32)
        res = self.stat_v.verify_flow(vec)

        self.assertIn("score", res)
        self.assertIn("strongly_contradictory", res)
        self.assertIn("details", res)
        self.assertGreaterEqual(res["score"], 0.0)
        self.assertLessEqual(res["score"], 1.0)
        self.assertIsInstance(res["strongly_contradictory"], bool)

    def test_behavioural_signal_causal_integrity(self):
        """Signal (c) must maintain causal integrity and never leak future traffic."""
        self.behav_v.reset_windows()
        meta = {"Source IP": "192.168.10.50", "Timestamp": "2026-10-26 10:00:00"}
        features = {"Flow Packets/s": 50, "Flow Bytes/s": 1000, "Flow Duration": 100000, "Packet Length Mean": 60}

        # Window should initially be empty before scoring
        self.assertNotIn("192.168.10.50", self.behav_v.rolling_windows)
        res = self.behav_v.verify_flow(meta, features, update_window=True)

        self.assertIn("score", res)
        self.assertGreaterEqual(res["score"], 0.0)
        self.assertLessEqual(res["score"], 1.0)
        # Window should have exactly 1 record AFTER scoring
        self.assertEqual(len(self.behav_v.rolling_windows["192.168.10.50"]), 1)

    def test_explanation_signal_contract_and_bounds(self):
        """Signal (d) must evaluate semantic alignment of top SHAP attribution features."""
        # Consistent explanation: DoS driven by Flow Duration and Flow Packets/s
        shap_consistent = [
            {"feature": "Flow Duration", "shap_value": 0.45},
            {"feature": "Flow Packets/s", "shap_value": 0.35},
            {"feature": "Init_Win_bytes_forward", "shap_value": 0.10},
        ]
        res = self.expl_v.verify_explanation("DoS/DDoS", shap_consistent)
        self.assertGreaterEqual(res["score"], 0.70)
        self.assertFalse(res["strongly_contradictory"])

        # Inconsistent explanation: DoS driven by non-DoS features
        shap_inconsistent = [
            {"feature": "Source Port", "shap_value": 0.50},
            {"feature": "Destination Port", "shap_value": 0.50},
        ]
        res_bad = self.expl_v.verify_explanation("DoS/DDoS", shap_inconsistent)
        self.assertLess(res_bad["score"], 0.20)
        self.assertTrue(res_bad["strongly_contradictory"])


class TestDecisionTable(unittest.TestCase):
    """Tests the Decision Table logic under synthetic edge cases."""

    def test_confirm_decision(self):
        """CONFIRM requires p_v >= 0.70 and 0 strongly contradictory signals."""
        r = {"score": 0.85, "strongly_contradictory": False, "details": {}}
        s = {"score": 0.80, "strongly_contradictory": False, "details": {}}
        b = {"score": 0.75, "strongly_contradictory": False, "details": {}}
        e = {"score": 0.80, "strongly_contradictory": False, "details": {}}

        dec = compute_verification_decision(r, s, b, e)
        self.assertEqual(dec["decision"], "CONFIRM")
        self.assertGreaterEqual(dec["p_v"], 0.70)
        self.assertIn("CONFIRM", dec["rationale"])

    def test_reduce_decision_partial_disagreement(self):
        """REDUCE when p_v is moderate [0.40, 0.70) or 1 signal strongly contradicts."""
        r = {"score": 0.90, "strongly_contradictory": False, "details": {}}
        s = {"score": 0.85, "strongly_contradictory": False, "details": {}}
        b = {"score": 0.10, "strongly_contradictory": True, "details": {}}  # 1 contradictory
        e = {"score": 0.80, "strongly_contradictory": False, "details": {}}

        dec = compute_verification_decision(r, s, b, e)
        self.assertEqual(dec["decision"], "REDUCE")
        self.assertIn("REDUCE", dec["rationale"])

    def test_reject_decision_score_below_threshold(self):
        """REJECT when p_v < 0.40."""
        r = {"score": 0.25, "strongly_contradictory": False, "details": {}}
        s = {"score": 0.30, "strongly_contradictory": False, "details": {}}
        b = {"score": 0.25, "strongly_contradictory": False, "details": {}}
        e = {"score": 0.35, "strongly_contradictory": False, "details": {}}

        dec = compute_verification_decision(r, s, b, e)
        self.assertEqual(dec["decision"], "REJECT")
        self.assertLess(dec["p_v"], 0.40)

    def test_reject_decision_multiple_contradictions(self):
        """REJECT when >= 2 signals strongly contradict, even if p_v is high."""
        r = {"score": 0.95, "strongly_contradictory": False, "details": {}}
        s = {"score": 0.10, "strongly_contradictory": True, "details": {}}   # Contradiction 1
        b = {"score": 0.15, "strongly_contradictory": True, "details": {}}   # Contradiction 2
        e = {"score": 0.90, "strongly_contradictory": False, "details": {}}

        dec = compute_verification_decision(r, s, b, e)
        self.assertEqual(dec["decision"], "REJECT")
        self.assertIn("Rejected due to 2 strongly contradictory signals", dec["rationale"])


class TestGroundTruthIsolation(unittest.TestCase):
    """
    CRITICAL ARCHITECTURAL CONSTRAINT:
    VerificationAgent must NEVER inspect ground_truth to make its decision.
    """

    def test_ground_truth_isolation(self):
        """Verifies that VerificationAgent gives identical output whether ground_truth is present or absent."""
        agent = VerificationAgent()

        meta = {
            "Source IP": "172.16.0.1",
            "Destination IP": "192.168.10.50",
            "Source Port": 50000,
            "Destination Port": 80,
            "Protocol": 6,
        }
        features = {
            "Flow Duration": 2000000,
            "Flow Packets/s": 5000,
            "Packet Length Mean": 400,
        }
        vec = np.zeros(68, dtype=np.float32)

        # Alert without ground truth
        alert_no_gt = create_empty_alert("test.csv", 0, meta, features)
        alert_no_gt["detection"]["predicted_class"] = "DoS/DDoS"
        alert_no_gt["detection"]["probability"] = 0.95
        alert_no_gt["detection"]["is_alert"] = True
        dec1 = agent.verify(alert_no_gt)

        # Alert with ground truth
        alert_with_gt = create_empty_alert(
            "test.csv", 0, meta, features,
            ground_truth={"label": "Benign", "project_class": "Benign"}
        )
        alert_with_gt["detection"]["predicted_class"] = "DoS/DDoS"
        alert_with_gt["detection"]["probability"] = 0.95
        alert_with_gt["detection"]["is_alert"] = True
        dec2 = agent.verify(alert_with_gt)

        # Assert identical decisions and agreement score
        self.assertEqual(dec1["decision"], dec2["decision"])
        self.assertEqual(dec1["p_v"], dec2["p_v"])

        # Validate Canonical Alert Schema
        self.assertTrue(validate_alert(alert_no_gt))
        self.assertTrue(validate_alert(alert_with_gt))


if __name__ == "__main__":
    unittest.main()
