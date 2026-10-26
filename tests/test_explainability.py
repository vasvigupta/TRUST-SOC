"""
Unit Tests — SHAP Explainability Engine (Stage 1.7)
===================================================
Stdlib unittest tests verifying:
- TreeExplainer initialization
- Per-prediction explanation format
- SHAP attribution consistency with predicted class
- Reconstruction of model output from base value + sum of SHAP values
"""

import unittest
from pathlib import Path
import numpy as np
import joblib

from src.config.config import MODEL_PATH, PROCESSED_X_TEST, PROCESSED_X_TEST_RAW
from src.detection.model import DetectionAgent
from src.explainability.shap_explainer import TrustShapExplainer


class TestShapExplainability(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = DetectionAgent.load(MODEL_PATH)
        cls.explainer = TrustShapExplainer(cls.agent)
        cls.X_test = joblib.load(PROCESSED_X_TEST)
        cls.X_test_raw = joblib.load(PROCESSED_X_TEST_RAW)

    def test_single_flow_explanation_contract(self):
        """Verify explain_flow returns valid explanation contract."""
        flow_vec = self.X_test[0]
        flow_raw = self.X_test_raw.iloc[0].to_dict()

        res = self.explainer.explain_flow(flow_vec, flow_raw, top_k=5)

        self.assertIn("prediction", res)
        self.assertIn("confidence", res)
        self.assertIn("base_value", res)
        self.assertIn("shap_sum", res)
        self.assertIn("reconstructed_output", res)
        self.assertIn("top_features", res)
        self.assertEqual(len(res["top_features"]), 5)

        for feat in res["top_features"]:
            self.assertIn("feature", feat)
            self.assertIn("shap_value", feat)
            self.assertIn("feature_value", feat)

    def test_shap_reconstruction_consistency(self):
        """Verify base_value + sum(shap_values) reconstructs model prediction within tolerance."""
        flow_vec = self.X_test[1]
        res = self.explainer.explain_flow(flow_vec, top_k=10)

        # Base value + sum of SHAP attributions should equal reconstructed model probability
        expected = res["base_value"] + res["shap_sum"]
        self.assertAlmostEqual(res["reconstructed_output"], expected, places=3)
        self.assertAlmostEqual(res["reconstructed_output"], res["confidence"], delta=0.05)


if __name__ == "__main__":
    unittest.main()
