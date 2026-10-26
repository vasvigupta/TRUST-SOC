"""
Unit Tests — Log Replay Simulator (Stage 1.8)
==============================================
Stdlib unittest tests verifying:
- Replay engine initialization and loading
- next() and next_n() return valid canonical alert objects
- Replay rate controls and queue buffering
"""

import unittest
from pathlib import Path

from src.config.config import REPLAY_SAMPLE_PATH
from src.ingestion.log_replay import LogReplaySimulator
from src.schemas.alert import validate_alert


class TestLogReplay(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.simulator = LogReplaySimulator(
            sample_path=REPLAY_SAMPLE_PATH,
            records_per_second=50.0,
            enable_shap=False  # Fast mode for unit test suite
        )

    def test_next_returns_valid_alert(self):
        """Verify next() generates a fully valid Canonical Alert."""
        alert = self.simulator.next()
        self.assertTrue(validate_alert(alert))
        self.assertIn("flow", alert)
        self.assertIn("detection", alert)
        self.assertIn(alert["verification"]["decision"], ["CONFIRM", "REDUCE", "REJECT", "CONFIRM_BENIGN"])

    def test_next_n_returns_exact_count(self):
        """Verify next_n(10) returns exactly 10 valid alerts."""
        alerts = self.simulator.next_n(10)
        self.assertEqual(len(alerts), 10)
        for a in alerts:
            self.assertTrue(validate_alert(a))

    def test_rate_adjustment(self):
        """Verify playback rate control."""
        self.simulator.set_rate(100.0)
        self.assertEqual(self.simulator.rate, 100.0)
        self.simulator.set_rate(0.01)  # clamped to >= 0.1
        self.assertEqual(self.simulator.rate, 0.1)


if __name__ == "__main__":
    unittest.main()
