"""
Unit Tests for Confidence Scoring Engine (Milestone 3 — Stage 3.1)
==================================================================
Tests:
1. Weight sum validation (alpha + beta + gamma = 1.0).
2. Clamping and bounds: C in [0.0, 1.0].
3. Exact threshold boundary transitions:
   - C >= 0.80 -> HIGH
   - 0.50 <= C < 0.80 -> MEDIUM
   - C < 0.50 -> LOW
4. Monotonicity: increasing any of p_d, p_v, r_corr cannot decrease C.
5. Prioritisation Matrix mappings.

Uses stdlib unittest only.
"""

import unittest
from src.scoring.confidence_scorer import ConfidenceScoringEngine


class TestConfidenceScoringEngine(unittest.TestCase):
    """Verifies mathematical correctness and boundary behavior of confidence scoring."""

    def setUp(self):
        self.scorer = ConfidenceScoringEngine()

    def test_weight_sum_validation(self):
        """Scoring engine must enforce that alpha + beta + gamma == 1.0."""
        # Valid weights
        valid_engine = ConfidenceScoringEngine({"alpha": 0.5, "beta": 0.3, "gamma": 0.2})
        self.assertAlmostEqual(valid_engine.alpha + valid_engine.beta + valid_engine.gamma, 1.0)

        # Invalid weights (sum != 1.0) must raise ValueError
        with self.assertRaises(ValueError):
            ConfidenceScoringEngine({"alpha": 0.5, "beta": 0.5, "gamma": 0.5})

    def test_composite_confidence_bounds(self):
        """Composite confidence C must always stay strictly within [0.0, 1.0]."""
        # Minimum extreme
        res_min = self.scorer.compute_confidence(p_d=0.0, p_v=0.0, r_corr=0.0)
        self.assertEqual(res_min["composite"], 0.0)
        self.assertEqual(res_min["band"], "LOW")

        # Maximum extreme
        res_max = self.scorer.compute_confidence(p_d=1.0, p_v=1.0, r_corr=1.0)
        self.assertEqual(res_max["composite"], 1.0)
        self.assertEqual(res_max["band"], "HIGH")

        # Clamping test with out-of-bound inputs
        res_clamp = self.scorer.compute_confidence(p_d=1.5, p_v=2.0, r_corr=-0.5)
        self.assertGreaterEqual(res_clamp["composite"], 0.0)
        self.assertLessEqual(res_clamp["composite"], 1.0)

    def test_exact_threshold_transitions(self):
        """Tests exact transitions at 0.80 (HIGH) and 0.50 (MEDIUM)."""
        # Exactly 0.80 -> HIGH
        # C = 0.4 * 1.0 + 0.4 * 0.8 + 0.2 * 0.4 = 0.4 + 0.32 + 0.08 = 0.80
        res_80 = self.scorer.compute_confidence(p_d=1.0, p_v=0.8, r_corr=0.4)
        self.assertAlmostEqual(res_80["composite"], 0.80, places=3)
        self.assertEqual(res_80["band"], "HIGH")

        # Just below 0.80 -> MEDIUM
        # C = 0.4 * 1.0 + 0.4 * 0.79 + 0.2 * 0.4 = 0.4 + 0.316 + 0.08 = 0.796
        res_79 = self.scorer.compute_confidence(p_d=1.0, p_v=0.79, r_corr=0.4)
        self.assertLess(res_79["composite"], 0.80)
        self.assertEqual(res_79["band"], "MEDIUM")

        # Exactly 0.50 -> MEDIUM
        # C = 0.4 * 0.5 + 0.4 * 0.5 + 0.2 * 0.5 = 0.50
        res_50 = self.scorer.compute_confidence(p_d=0.5, p_v=0.5, r_corr=0.5)
        self.assertAlmostEqual(res_50["composite"], 0.50, places=3)
        self.assertEqual(res_50["band"], "MEDIUM")

        # Just below 0.50 -> LOW
        # C = 0.4 * 0.4 + 0.4 * 0.5 + 0.2 * 0.5 = 0.16 + 0.20 + 0.10 = 0.46
        res_46 = self.scorer.compute_confidence(p_d=0.4, p_v=0.5, r_corr=0.5)
        self.assertLess(res_46["composite"], 0.50)
        self.assertEqual(res_46["band"], "LOW")

    def test_monotonicity(self):
        """Increasing any parameter (p_d, p_v, r_corr) must strictly not decrease C."""
        base_c = self.scorer.compute_confidence(0.6, 0.6, 0.6)["composite"]

        higher_pd = self.scorer.compute_confidence(0.8, 0.6, 0.6)["composite"]
        higher_pv = self.scorer.compute_confidence(0.6, 0.8, 0.6)["composite"]
        higher_rc = self.scorer.compute_confidence(0.6, 0.6, 0.8)["composite"]

        self.assertGreater(higher_pd, base_c)
        self.assertGreater(higher_pv, base_c)
        self.assertGreater(higher_rc, base_c)

    def test_prioritisation_actions(self):
        """Verifies operational actions in Prioritisation Matrix."""
        # CONFIRM + High p_d -> AUTO_ESCALATE
        res_esc = self.scorer.compute_confidence(p_d=0.95, p_v=0.85, r_corr=0.90, verification_decision="CONFIRM")
        self.assertEqual(res_esc["action"], "AUTO_ESCALATE")

        # REJECT -> FALSE_POSITIVE_LOG (even if raw p_d was high)
        res_rej = self.scorer.compute_confidence(p_d=0.99, p_v=0.35, r_corr=0.10, verification_decision="REJECT")
        self.assertEqual(res_rej["action"], "FALSE_POSITIVE_LOG")
        self.assertEqual(res_rej["matrix_action"], "FALSE_POSITIVE_LOGGED")


if __name__ == "__main__":
    unittest.main()
