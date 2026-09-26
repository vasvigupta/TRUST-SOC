"""
TRUST-SOC — Master Run Script
===============================
Run the complete pipeline end-to-end.

Usage:
    python run.py --stage all         # run everything
    python run.py --stage preprocess
    python run.py --stage train
    python run.py --stage evaluate
    python run.py --stage shap
    python run.py --stage replay
    python run.py --stage ui
"""

import sys
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("TRUST-SOC.run")

STAGES = ["preprocess", "train", "evaluate", "shap", "replay", "api", "all"]


def run_stage(stage: str):
    if stage in ("preprocess", "all"):
        log.info("\n" + "=" * 60)
        log.info("STAGE 2 — PREPROCESSING")
        from src.preprocessing.preprocess import run_preprocessing
        run_preprocessing()

    if stage in ("train", "all"):
        log.info("\n" + "=" * 60)
        log.info("STAGE 3 — TRAINING DETECTION AGENT")
        from src.detection.train import train
        train()

    if stage in ("evaluate", "all"):
        log.info("\n" + "=" * 60)
        log.info("STAGE 4 — EVALUATION")
        from src.detection.predict import evaluate
        evaluate()

    if stage in ("shap", "all"):
        log.info("\n" + "=" * 60)
        log.info("STAGE 5 — SHAP EXPLAINABILITY")
        from src.explainability.shap_explainer import run_shap_analysis
        run_shap_analysis()

    if stage in ("replay", "all"):
        log.info("\n" + "=" * 60)
        log.info("STAGE 6 — LOG REPLAY DEMO")
        from src.ingestion.log_replay import run_replay
        run_replay()

    if stage in ("api", "all"):
        log.info("\n" + "=" * 60)
        log.info("STAGE 7 — FASTAPI BACKEND SERVER")
        import uvicorn
        from src.config.config import API_HOST, API_PORT
        log.info(f"Starting FastAPI server on http://{API_HOST}:{API_PORT} ...")
        if stage == "api":
            uvicorn.run("src.api.main:app", host=API_HOST, port=API_PORT, reload=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TRUST-SOC pipeline runner")
    parser.add_argument(
        "--stage",
        choices=STAGES,
        default="all",
        help="Pipeline stage to run (default: all)",
    )
    args = parser.parse_args()
    log.info(f"Running stage: {args.stage}")
    run_stage(args.stage)
    log.info("\nDone.")
