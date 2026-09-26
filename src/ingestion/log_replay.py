"""
Log Replay Pipeline
====================
Simulates a SOC receiving network-flow records one-by-one
from a historical CICIDS2017 CSV (the preprocessed test sample).

Flow:
  CSV row → preprocess → DetectionAgent → probability → SHAP → Alert

This is NOT real-time traffic capture.
It is a controlled replay of historical records to simulate
the SOC ingestion pipeline.
"""

import sys
import json
import time
import logging
import datetime
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Iterator, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.config.config import (
    REPLAY_SAMPLE_PATH, REPLAY_N_RECORDS, REPLAY_DELAY_SEC,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("TRUST-SOC.replay")


# ─────────────────────────────────────────────────────────────────
# Alert Structure
# ─────────────────────────────────────────────────────────────────

def build_alert(
    flow_id: int,
    prediction: str,
    probability: float,
    top_features: list,
    class_probabilities: dict,
    true_label: Optional[str] = None,
) -> dict:
    """
    Build the internal alert object.

    Future fields (NOT yet implemented):
        verification_result, verification_confidence,
        corroboration, final_confidence, severity, mitre_tactic, evidence
    """
    alert = {
        "alert_id":           f"ALERT-{flow_id:05d}",
        "timestamp":          datetime.datetime.utcnow().isoformat() + "Z",
        "flow_index":         flow_id,

        # ── Detection Agent output ────────────────────────────────
        "prediction":         prediction,
        "probability":        round(probability, 4),
        "class_probabilities": {k: round(v, 4) for k, v in class_probabilities.items()},
        "top_features":       top_features,

        "status":             "DETECTED",

        # ── Ground truth (only present during evaluation replay) ──
        "true_label":         true_label,

        # ── Future Verification Agent fields (stubs) ──────────────
        "verification_result":     "NOT_IMPLEMENTED",
        "verification_confidence": None,
        "final_confidence":        None,
        "severity":                None,
        "mitre_tactic":            None,
    }
    return alert


# ─────────────────────────────────────────────────────────────────
# Replay Engine
# ─────────────────────────────────────────────────────────────────

class LogReplayEngine:
    """
    Replays preprocessed network-flow records one at a time.

    Parameters
    ----------
    agent : DetectionAgent
        A loaded DetectionAgent.
    sample_path : Path
        CSV produced by preprocessing (scaled features + TrustSOC_Label).
    use_shap : bool
        Whether to include per-record SHAP explanation (slower).
    delay : float
        Seconds to wait between records (0 = max speed).
    """

    def __init__(self, agent, sample_path: Path = REPLAY_SAMPLE_PATH,
                 use_shap: bool = True, delay: float = REPLAY_DELAY_SEC):
        self.agent       = agent
        self.delay       = delay
        self.use_shap    = use_shap
        self._df         = None
        self._pos        = 0
        self._running    = False
        self.sample_path = sample_path

    def load(self):
        """Load the replay CSV."""
        if not self.sample_path.exists():
            raise FileNotFoundError(
                f"ERROR: Replay sample not found at {self.sample_path}.\n"
                "Run preprocessing first:  python -m src.preprocessing.preprocess"
            )
        self._df  = pd.read_csv(self.sample_path)
        self._pos = 0
        log.info(f"Replay dataset loaded: {len(self._df)} records  ← {self.sample_path.name}")
        return self

    def start(self):
        self._running = True
        self._pos     = 0
        log.info("Replay STARTED.")

    def stop(self):
        self._running = False
        log.info(f"Replay STOPPED at record {self._pos}.")

    def reset(self):
        self._pos     = 0
        self._running = False

    @property
    def remaining(self):
        return max(0, len(self._df) - self._pos) if self._df is not None else 0

    def _process_row(self, idx: int) -> dict:
        """Run the full pipeline on one row."""
        row = self._df.iloc[idx]

        # Separate ground-truth label (present in sample file)
        true_enc  = row.get("TrustSOC_Label", None)
        true_label = None
        if true_enc is not None:
            try:
                true_label = self.agent.encoder.inverse_transform([int(true_enc)])[0]
            except Exception:
                true_label = str(true_enc)

        # Features only
        feature_cols = [c for c in self._df.columns if c != "TrustSOC_Label"]
        x_row = row[feature_cols]

        # Detection
        result = self.agent.predict_single(x_row)

        # SHAP explanation (optional — can be slow per record)
        top_features = []
        if self.use_shap:
            try:
                from src.explainability.shap_explainer import explain_single_prediction
                expl = explain_single_prediction(
                    self.agent, x_row,
                    list(self.agent.encoder.classes_)
                )
                top_features = expl["top_features"]
            except Exception as e:
                log.debug(f"SHAP per-record skipped: {e}")

        alert = build_alert(
            flow_id             = idx,
            prediction          = result["prediction"],
            probability         = result["confidence"],
            top_features        = top_features,
            class_probabilities = result["class_probabilities"],
            true_label          = true_label,
        )
        return alert

    def next_record(self) -> Optional[dict]:
        """Process the next record and advance the position."""
        if self._df is None:
            raise RuntimeError("Call .load() before replaying.")
        if self._pos >= len(self._df):
            log.info("Replay: end of dataset reached.")
            self._running = False
            return None

        alert     = self._process_row(self._pos)
        self._pos += 1
        if self.delay > 0:
            time.sleep(self.delay)
        return alert

    def replay_n(self, n: int = REPLAY_N_RECORDS) -> list:
        """Process the next n records. Returns list of alerts."""
        alerts = []
        for _ in range(n):
            alert = self.next_record()
            if alert is None:
                break
            alerts.append(alert)
        return alerts

    def stream(self) -> Iterator[dict]:
        """Generator: yields alerts one by one until dataset is exhausted."""
        self.start()
        while self._running and self._pos < len(self._df):
            yield self.next_record()


# ─────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────

def run_replay(n: int = REPLAY_N_RECORDS, use_shap: bool = False):
    """
    Demo replay: process n records from the sample CSV and print alerts.
    SHAP is OFF by default for speed in CLI demo.
    """
    from src.detection.model import DetectionAgent

    log.info("=" * 60)
    log.info("TRUST-SOC  |  Log Replay Demo")
    log.info("=" * 60)

    agent  = DetectionAgent.load()
    engine = LogReplayEngine(agent, use_shap=use_shap)
    engine.load()
    engine.start()

    alerts = engine.replay_n(n)

    log.info(f"\nProcessed {len(alerts)} flow records:\n")
    for a in alerts:
        match = "✓" if a["true_label"] == a["prediction"] else "✗"
        log.info(
            f"  [{match}] Flow {a['flow_index']:>4}  "
            f"Pred: {a['prediction']:<15}  "
            f"Prob: {a['probability']:.3f}  "
            f"True: {a['true_label']}"
        )

    engine.stop()

    # Save sample alerts
    out_path = Path("results") / "reports" / "sample_alerts.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(alerts[:10], f, indent=2)
    log.info(f"\nFirst 10 alerts saved → {out_path}")

    log.info("=" * 60)
    log.info("Replay COMPLETE.")
    log.info("=" * 60)
    return alerts


if __name__ == "__main__":
    run_replay()
