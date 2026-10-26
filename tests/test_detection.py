"""
Unit Tests — Detection Agent (Stage 1.4 & 1.5)
==============================================
Stdlib unittest tests verifying:
- Model load / reload parity
- Predict and predict_proba outputs
- Probability sums to 1.0
- detect() single-flow inference interface
- Alert flag correctness
"""

import unittest
from pathlib import Path
import numpy as np
import joblib

from src.config.config import MODEL_PATH, PROCESSED_X_TEST, ENCODER_PATH, FEATURE_NAMES_PATH
from src.detection.model import DetectionAgent


class TestDetectionAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = DetectionAgent.load(MODEL_PATH)
        cls.encoder = joblib.load(ENCODER_PATH)
        cls.feature_names = joblib.load(FEATURE_NAMES_PATH)
        cls.X_test = joblib.load(PROCESSED_X_TEST)

    def test_model_loaded(self):
        """Verify DetectionAgent loaded successfully."""
        self.assertIsNotNone(self.agent.classifier)
        self.assertIsNotNone(self.agent.encoder)
        self.assertEqual(len(self.agent.feature_names), len(self.feature_names))

    def test_predict_shape_and_classes(self):
        """Verify predict output shape and valid class indices."""
        sample_X = self.X_test[:25]
        preds = self.agent.predict(sample_X)
        self.assertEqual(preds.shape, (25,))
        self.assertTrue(all(0 <= p < len(self.encoder.classes_) for p in preds))

    def test_predict_proba_sums_to_one(self):
        """Verify probability distribution sums to 1.0 across all samples."""
        sample_X = self.X_test[:50]
        probs = self.agent.predict_proba(sample_X)
        self.assertEqual(probs.shape, (50, len(self.encoder.classes_)))

        row_sums = np.sum(probs, axis=1)
        np.testing.assert_allclose(
            row_sums, 1.0, atol=1e-4,
            err_msg="Probability rows do not sum to 1.0!"
        )

    def test_detect_single_flow_interface(self):
        """Verify detect() contract: {predicted_class, probability, class_probabilities, is_alert}."""
        single_vec = self.X_test[0]
        out = self.agent.detect(single_vec)

        self.assertIn("predicted_class", out)
        self.assertIn("probability", out)
        self.assertIn("class_probabilities", out)
        self.assertIn("is_alert", out)

        self.assertIn(out["predicted_class"], self.encoder.classes_)
        self.assertAlmostEqual(sum(out["class_probabilities"].values()), 1.0, delta=1e-2)

        if out["predicted_class"] == "Benign":
            self.assertFalse(out["is_alert"])
        else:
            self.assertTrue(out["is_alert"])


if __name__ == "__main__":
    unittest.main()
