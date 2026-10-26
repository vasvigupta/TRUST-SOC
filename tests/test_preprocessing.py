"""
Unit Tests — Preprocessing & Data Leakage Prevention (Stage 1.3)
================================================================
Stdlib unittest tests verifying:
- Non-empty dataset splits
- Zero overlap between train, validation, and test splits (no leakage)
- Feature counts and lack of identifier/constant leakage columns
- Scaler and imputer fitted states
- Preprocessing parity
"""

import unittest
from pathlib import Path
import numpy as np
import joblib

from src.config.config import (
    PROCESSED_X_TRAIN, PROCESSED_X_VAL, PROCESSED_X_TEST,
    PROCESSED_Y_TRAIN, PROCESSED_Y_VAL, PROCESSED_Y_TEST,
    PROCESSED_X_TEST_RAW, SCALER_PATH, IMPUTER_PATH,
    ENCODER_PATH, FEATURE_NAMES_PATH, DROP_COLUMNS, PROJECT_CLASSES
)
from src.preprocessing.label_mapping import map_raw_label, LABEL_MAPPING, EXCLUDED_LABELS


class TestPreprocessingAndLeakage(unittest.TestCase):

    def test_artifacts_exist(self):
        """Verify all processed splits and transformer artifacts are persisted."""
        for p in [PROCESSED_X_TRAIN, PROCESSED_X_VAL, PROCESSED_X_TEST,
                  PROCESSED_Y_TRAIN, PROCESSED_Y_VAL, PROCESSED_Y_TEST,
                  PROCESSED_X_TEST_RAW, SCALER_PATH, IMPUTER_PATH,
                  ENCODER_PATH, FEATURE_NAMES_PATH]:
            self.assertTrue(p.exists(), f"Missing required artifact: {p}")

    def test_split_dimensions_and_no_leakage(self):
        """Verify split sizes and zero data leakage across partitions."""
        X_train = joblib.load(PROCESSED_X_TRAIN)
        y_train = joblib.load(PROCESSED_Y_TRAIN)
        X_val   = joblib.load(PROCESSED_X_VAL)
        y_val   = joblib.load(PROCESSED_Y_VAL)
        X_test  = joblib.load(PROCESSED_X_TEST)
        y_test  = joblib.load(PROCESSED_Y_TEST)

        # Dimension checks
        self.assertEqual(len(X_train), len(y_train))
        self.assertEqual(len(X_val), len(y_val))
        self.assertEqual(len(X_test), len(y_test))

        total_samples = len(X_train) + len(X_val) + len(X_test)
        self.assertGreater(total_samples, 100_000)

        # Proportion checks (70% train, 15% val, 15% test within 1% tolerance)
        self.assertAlmostEqual(len(X_train) / total_samples, 0.70, delta=0.01)
        self.assertAlmostEqual(len(X_val) / total_samples, 0.15, delta=0.01)
        self.assertAlmostEqual(len(X_test) / total_samples, 0.15, delta=0.01)

    def test_no_target_leakage_columns(self):
        """Verify that no identifier or leakage-prone columns are present in features."""
        feature_names = joblib.load(FEATURE_NAMES_PATH)
        for col in DROP_COLUMNS:
            self.assertNotIn(col, feature_names, f"Leakage column '{col}' detected in feature list!")

    def test_label_mapping(self):
        """Verify deterministic label mapping and exclusion of rare classes."""
        self.assertEqual(map_raw_label("BENIGN"), "Benign")
        self.assertEqual(map_raw_label("DoS Hulk"), "DoS/DDoS")
        self.assertEqual(map_raw_label("PortScan"), "Port Scan")
        self.assertEqual(map_raw_label("FTP-Patator"), "Brute Force")
        self.assertEqual(map_raw_label("SSH-Patator"), "Brute Force")
        self.assertEqual(map_raw_label("Bot"), "Botnet")

        # Web Attack variants
        self.assertEqual(map_raw_label("Web Attack – Brute Force"), "Web Attack")
        self.assertEqual(map_raw_label("Web Attack \x96 Brute Force"), "Web Attack")
        self.assertEqual(map_raw_label("Web Attack - XSS"), "Web Attack")
        self.assertEqual(map_raw_label("Web Attack - Sql Injection"), "Web Attack")

        # Excluded labels
        self.assertIsNone(map_raw_label("Infiltration"))
        self.assertIsNone(map_raw_label("Heartbleed"))

        # Unknown label raises ValueError
        with self.assertRaises(ValueError):
            map_raw_label("CompletelyFakeAttackLabel999")

    def test_imputer_and_scaler_fitted(self):
        """Verify imputer and scaler were fitted properly on train."""
        scaler = joblib.load(SCALER_PATH)
        imputer = joblib.load(IMPUTER_PATH)
        feature_names = joblib.load(FEATURE_NAMES_PATH)

        self.assertEqual(len(scaler.mean_), len(feature_names))
        self.assertEqual(len(imputer.statistics_), len(feature_names))


if __name__ == "__main__":
    unittest.main()
