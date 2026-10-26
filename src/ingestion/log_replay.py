"""
Log Ingestion & Flow Replay Simulator (Stage 1.8)
=================================================
Simulates a SOC streaming ingestion feed using Python generator + queue.Queue.
No external message brokers (Kafka/RabbitMQ) required, but message payloads
are strictly Kafka-compatible (key, timestamp, JSON payload).

Controls:
    start() | pause() | resume() | next() | next_n(n) | stop() | set_rate()

Flow lifecycle:
    Replay CSV record -> Common JSON flow schema (Section 5)
    -> Exact Training Scaler/Imputer -> Detection Agent
    -> SHAP TreeExplainer Top-k Attributions
    -> Canonical Alert Object (Verification = NOT_IMPLEMENTED)
"""

import time
import json
import uuid
import queue
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Iterator, Dict, Any, List, Optional
import numpy as np
import pandas as pd
import joblib

from src.config.config import (
    REPLAY_SAMPLE_PATH, SCALER_PATH, IMPUTER_PATH, ENCODER_PATH,
    FEATURE_NAMES_PATH, MODEL_PATH, REPORTS_DIR, REPLAY_DEFAULT_RATE
)
from src.schemas.alert import create_empty_alert, validate_alert
from src.detection.model import DetectionAgent
from src.explainability.shap_explainer import TrustShapExplainer
from src.verification.verification_agent import VerificationAgent
from src.scoring.confidence_scorer import ConfidenceScoringEngine
from src.database.db import init_db
from src.database.alert_store import insert_alert

log = logging.getLogger("TRUST-SOC.replay")


class LogReplaySimulator:
    """
    Controlled-rate replay simulator for SOC alert generation.
    """

    def __init__(
        self,
        sample_path: Path = REPLAY_SAMPLE_PATH,
        records_per_second: float = REPLAY_DEFAULT_RATE,
        enable_shap: bool = True
    ):
        self.sample_path = Path(sample_path)
        self.rate = float(records_per_second)
        self.enable_shap = enable_shap

        if not self.sample_path.exists():
            raise FileNotFoundError(
                f"ERROR: Replay dataset not found at {self.sample_path}.\n"
                "Run: python run.py preprocess"
            )

        log.info(f"Loading replay source data from {self.sample_path}...")
        self.df = pd.read_csv(self.sample_path)
        log.info(f"Loaded {len(self.df):,} replayed flows available in buffer.")

        # Load exact preprocessing & detection artifacts
        log.info("Loading fitted preprocessing artifacts and Detection Agent...")
        self.scaler = joblib.load(SCALER_PATH)
        self.imputer = joblib.load(IMPUTER_PATH)
        self.encoder = joblib.load(ENCODER_PATH)
        self.feature_names = joblib.load(FEATURE_NAMES_PATH)

        self.detector = DetectionAgent.load(MODEL_PATH)
        self.verifier = VerificationAgent()
        self.scorer = ConfidenceScoringEngine()
        init_db()

        if self.enable_shap:
            self.explainer = TrustShapExplainer(self.detector)
        else:
            self.explainer = None

        # Queue & state management
        self.queue = queue.Queue(maxsize=1000)
        self._current_index = 0
        self._is_running = False
        self._is_paused = False
        self._worker_thread: Optional[threading.Thread] = None

    def set_rate(self, records_per_second: float):
        """Adjusts the playback rate in records per second."""
        self.rate = max(0.1, float(records_per_second))
        log.info(f"Replay rate set to {self.rate} records/second.")

    def _normalize_raw_record(self, row: pd.Series, row_idx: int) -> Dict[str, Any]:
        """
        Normalizes a CSV row into a Kafka-compatible message with Section 5 flow block.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        # Available network metadata fields
        meta_keys = [
            "Flow ID", "Source IP", "Source Port",
            "Destination IP", "Destination Port", "Protocol", "Timestamp"
        ]
        fields_available = {}
        for k in meta_keys:
            if k in row:
                val = row[k]
                fields_available[k] = int(val) if isinstance(val, (int, np.integer)) else str(val)

        source_file = str(row.get("source_file", "CICIDS2017_replay_stream.csv"))

        # Raw unscaled features dictionary
        features = {}
        for fname in self.feature_names:
            features[fname] = float(row[fname]) if fname in row else 0.0

        # Ground truth block for evaluation ONLY
        orig_label = str(row.get("Label", row.get("project_class", "Unknown")))
        proj_class = str(row.get("project_class", "Benign"))
        is_attack = (proj_class != "Benign")

        ground_truth = {
            "original_label": orig_label,
            "project_class": proj_class,
            "is_attack": is_attack
        }

        return {
            "key": f"flow:{row_idx}",
            "timestamp": now_iso,
            "source_file": source_file,
            "row_index": row_idx,
            "fields_available": fields_available,
            "features": features,
            "ground_truth": ground_truth
        }

    def process_record(self, raw_msg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a normalized raw flow message through Detection -> SHAP -> Verification.
        Returns a valid Canonical Alert object (Section 5).
        """
        row_idx = raw_msg["row_index"]
        features_dict = raw_msg["features"]
        fields_available = raw_msg["fields_available"]
        source_file = raw_msg["source_file"]
        ground_truth = raw_msg["ground_truth"]

        # 1. Initialize schema
        alert = create_empty_alert(
            source_file=source_file,
            row_index=row_idx,
            fields_available=fields_available,
            features=features_dict,
            ground_truth=ground_truth,
            alert_id=f"alert-{uuid.uuid4().hex[:8]}:{row_idx}"
        )

        # 2. Extract feature vector and apply exact fitted preprocessing
        raw_vec = np.array([features_dict[f] for f in self.feature_names], dtype=np.float32).reshape(1, -1)
        raw_vec_clean = np.where(np.isinf(raw_vec), np.nan, raw_vec)
        imp_vec = self.imputer.transform(raw_vec_clean)
        scaled_vec = self.scaler.transform(imp_vec).astype(np.float32)

        # 3. Detection Agent inference
        det_out = self.detector.detect(scaled_vec[0])
        alert["detection"] = {
            "model": self.detector.model_type,
            "predicted_class": det_out["predicted_class"],
            "probability": det_out["probability"],
            "class_probabilities": det_out["class_probabilities"],
            "top_features": [],
            "is_alert": det_out["is_alert"],
        }
        alert["audit_trail"].append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "detection",
            "event": f"Classified as {det_out['predicted_class']} (p={det_out['probability']})"
        })

        # 4. SHAP explainability (computed for all flows, essential for alerts)
        if self.enable_shap and self.explainer:
            shap_out = self.explainer.explain_flow(
                scaled_vec[0],
                flow_raw=features_dict,
                top_k=5
            )
            alert["detection"]["top_features"] = shap_out["top_features"]
            alert["audit_trail"].append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "stage": "explainability",
                "event": f"Generated top-{len(shap_out['top_features'])} SHAP feature attributions ({shap_out['explanation_latency_ms']}ms)"
            })

        # 5. Verification Agent (Milestone 2 Active)
        ver_block = self.verifier.verify(alert)
        alert["verification"] = ver_block
        alert["audit_trail"].append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "verification",
            "event": f"Verification completed: {ver_block['decision']} (p_v={ver_block['p_v']})"
        })

        # 6. Confidence Scoring Engine (Milestone 3 Active)
        self.scorer.score_alert(alert)

        # 7. Persist to SQLite Database (Milestone 3 Active)
        insert_alert(alert)

        # Validate schema contract
        validate_alert(alert)
        return alert

    def _worker_loop(self, max_records: Optional[int]):
        """Background thread feeding the replay queue."""
        processed_count = 0
        while self._is_running:
            if self._is_paused:
                time.sleep(0.05)
                continue

            if max_records is not None and processed_count >= max_records:
                log.info(f"Replay reached requested max records limit ({max_records}).")
                break

            if self._current_index >= len(self.df):
                log.info("Reached end of replay dataset. Wrapping to beginning.")
                self._current_index = 0

            row = self.df.iloc[self._current_index]
            row_idx = self._current_index
            self._current_index += 1
            processed_count += 1

            raw_msg = self._normalize_raw_record(row, row_idx)
            alert = self.process_record(raw_msg)

            self.queue.put(alert)

            # Rate throttling
            delay = 1.0 / self.rate
            time.sleep(delay)

        self._is_running = False

    # ── Replay API Controls ──────────────────────────────────────────

    def start(self, max_records: Optional[int] = None, rate: Optional[float] = None):
        """Starts replay in background thread."""
        if rate is not None:
            self.set_rate(rate)

        if self._is_running and not self._is_paused:
            log.warning("Replay is already running.")
            return

        if self._is_paused:
            self.resume()
            return

        self._is_running = True
        self._is_paused = False
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            args=(max_records,),
            daemon=True
        )
        self._worker_thread.start()
        log.info(f"Replay started at {self.rate} records/sec.")

    def pause(self):
        """Pauses the replay playback."""
        self._is_paused = True
        log.info("Replay paused.")

    def resume(self):
        """Resumes the replay playback."""
        self._is_paused = False
        log.info("Replay resumed.")

    def stop(self):
        """Stops the replay simulator completely."""
        self._is_running = False
        self._is_paused = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)
        log.info("Replay stopped.")

    def next(self) -> Dict[str, Any]:
        """Synchronously processes and returns the next flow alert."""
        if self._current_index >= len(self.df):
            self._current_index = 0

        row = self.df.iloc[self._current_index]
        row_idx = self._current_index
        self._current_index += 1

        raw_msg = self._normalize_raw_record(row, row_idx)
        return self.process_record(raw_msg)

    def next_n(self, n: int) -> List[Dict[str, Any]]:
        """Synchronously processes and returns next n flow alerts."""
        alerts = []
        for _ in range(n):
            alerts.append(self.next())
        return alerts


def run_replay(n_records: int = 50):
    """
    CLI runner for Stage 1.8 Log Replay.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    log.info(f"Starting Stage 1.8 Log Replay Simulator ({n_records} flows)...")

    simulator = LogReplaySimulator(enable_shap=True)
    alerts = simulator.next_n(n_records)

    log.info(f"Successfully replayed and processed {len(alerts)} flows.")

    # Show first 5 alerts
    print("\n" + "=" * 80)
    print("SAMPLE REPLAYED DETECTION ALERTS (First 5):")
    print("=" * 80)
    for i, a in enumerate(alerts[:5], 1):
        det = a["detection"]
        flow = a["flow"]
        gt = a["ground_truth"]
        top_f_str = ", ".join([f"{f['feature']}={f['shap_value']:+.3f}" for f in det["top_features"][:3]])
        print(f"[{i:02d}] Alert ID: {a['alert_id']}")
        print(f"     Time:       {a['ingested_at']}")
        print(f"     Prediction: {det['predicted_class']:<12} (prob={det['probability']:.4f}) | Is Alert: {det['is_alert']}")
        print(f"     GroundTruth: {gt['project_class']:<12} (Raw: {gt['original_label']})")
        print(f"     Top SHAP:   {top_f_str}")
        print(f"     Verification: {a['verification']['decision']} (M1 Placeholder)")
        print("-" * 80)

    # Save to results/reports/sample_alerts.json
    out_path = REPORTS_DIR / "sample_alerts.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    log.info(f"Saved {len(alerts)} sample alerts to {out_path}")

    return alerts


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_replay(50)
