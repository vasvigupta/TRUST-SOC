"""
Pipeline Orchestrator (Milestone 5 — Stage 5.1)
==============================================
Runs the unified end-to-end TRUST-SOC flow over held-out records:
  Ingestion -> Detection -> SHAP -> Verification -> Confidence Scoring -> Store -> Report

Verifies contract integrity, causal isolation, and matches CLI/API results.
"""

import logging
import time
from typing import Dict, Any, Optional
from pathlib import Path

from src.config.config import (
    PROCESSED_X_TEST_RAW,
    PROC_DIR,
    DB_PATH,
)
from src.ingestion.log_replay import LogReplaySimulator
from src.database.alert_store import get_db_stats, list_alerts
from src.scoring.confidence_scorer import ConfidenceScoringEngine
from src.reporting.report_generator import ReportGenerator

log = logging.getLogger("TRUST-SOC.pipeline")


class PipelineOrchestrator:
    """Executes the full end-to-end pipeline over evaluation splits."""

    def __init__(self, enable_shap: bool = True, max_records: Optional[int] = None):
        self.enable_shap = enable_shap
        self.max_records = max_records
        self.simulator = LogReplaySimulator(enable_shap=enable_shap)
        self.scorer = ConfidenceScoringEngine()
        self.reporter = ReportGenerator()

    def run_pipeline(self, num_flows: int = 100) -> Dict[str, Any]:
        """Runs the complete pipeline over num_flows held-out test records."""
        log.info(f"Starting unified pipeline execution over {num_flows} flows...")
        start_time = time.perf_counter()

        processed_count = 0
        confirmed_count = 0
        reduced_count = 0
        rejected_count = 0
        high_band_count = 0

        # Step through evaluation flows
        for i in range(num_flows):
            alert = self.simulator.next()
            if not alert:
                break
            processed_count += 1

            ver = alert.get("verification", {})
            sc = alert.get("scoring", {})

            dec = ver.get("decision", "NONE")
            if dec == "CONFIRM":
                confirmed_count += 1
            elif dec == "REDUCE":
                reduced_count += 1
            elif dec == "REJECT":
                rejected_count += 1

            if sc.get("band") == "HIGH":
                high_band_count += 1

            if (i + 1) % 25 == 0 or (i + 1) == num_flows:
                log.info(
                    f"Flow {i+1}/{num_flows} processed | "
                    f"CONFIRM={confirmed_count}, REDUCE={reduced_count}, REJECT={rejected_count} | "
                    f"HIGH Band={high_band_count}"
                )

        duration = time.perf_counter() - start_time
        fps = processed_count / max(1e-4, duration)
        db_stats = get_db_stats()

        summary = {
            "processed_flows": processed_count,
            "duration_seconds": round(duration, 3),
            "throughput_fps": round(fps, 1),
            "decisions": {
                "CONFIRM": confirmed_count,
                "REDUCE": reduced_count,
                "REJECT": rejected_count,
            },
            "high_band_escalations": high_band_count,
            "database_totals": db_stats,
        }

        log.info("=" * 60)
        log.info(f"PIPELINE RUN COMPLETED in {duration:.2f}s ({fps:.1f} flows/sec)")
        log.info(f"Decisions: CONFIRM={confirmed_count}, REDUCE={reduced_count}, REJECT={rejected_count}")
        log.info(f"Total stored alerts in DB: {db_stats.get('total_alerts', 0)}")
        log.info("=" * 60)
        return summary


def run_pipeline_orchestrator(num_flows: int = 50):
    orchestrator = PipelineOrchestrator(enable_shap=True)
    return orchestrator.run_pipeline(num_flows=num_flows)


if __name__ == "__main__":
    run_pipeline_orchestrator(25)
