"""
TRUST-SOC — Master CLI Entry Point
==================================
Subcommands per Section 7.7:
    python run.py explore       # Stage 1.1: Dataset exploration & report
    python run.py preprocess    # Stage 1.3: Clean, split, scale, extract features
    python run.py train         # Stage 1.4: Train Detection Agent (RF / XGBoost)
    python run.py evaluate      # Stage 1.5: Evaluate Detection Agent baseline & FPR
    python run.py explain       # Stage 1.7: SHAP explainability analysis
    python run.py replay        # Stage 1.8: Streamlit / log replay flow simulation
    python run.py verify        # Milestone 2: Verification Agent
    python run.py score         # Milestone 3: Confidence scoring & bands
    python run.py report        # Milestone 3: Evidence report generator (JSON / PDF)
    python run.py serve         # Milestone 4: FastAPI server & React frontend
    python run.py pipeline      # Milestone 3/5: End-to-end pipeline run
    python run.py evaluate-all  # Milestone 5: Full evaluation & metrics regeneration
"""

import sys
import argparse
import logging
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("TRUST-SOC.cli")

SUBCOMMANDS = [
    "explore",
    "preprocess",
    "train",
    "evaluate",
    "explain",
    "replay",
    "verify",
    "score",
    "report",
    "serve",
    "pipeline",
    "evaluate-all",
    "all",
]


def run_command(command: str):
    if command == "explore":
        log.info("=" * 60)
        log.info("STAGE 1.1 — DATASET EXPLORATION & QUALITY AUDIT")
        log.info("=" * 60)
        from src.preprocessing.explore import explore_dataset
        explore_dataset()

    elif command in ("preprocess", "all"):
        log.info("=" * 60)
        log.info("STAGE 1.3 — PREPROCESSING PIPELINE & STRATIFIED SPLIT")
        log.info("=" * 60)
        from src.preprocessing.preprocess import run_preprocessing
        run_preprocessing()

    elif command in ("train", "all"):
        log.info("=" * 60)
        log.info("STAGE 1.4 — TRAINING DETECTION AGENT")
        log.info("=" * 60)
        from src.detection.train import train
        train()

    elif command in ("evaluate", "all"):
        log.info("=" * 60)
        log.info("STAGE 1.5 — EVALUATION & BASELINE FPR")
        log.info("=" * 60)
        from src.detection.predict import evaluate
        evaluate()

    elif command in ("explain", "all"):
        log.info("=" * 60)
        log.info("STAGE 1.7 — SHAP EXPLAINABILITY")
        log.info("=" * 60)
        from src.explainability.shap_explainer import run_shap_analysis
        run_shap_analysis()

    elif command in ("replay", "all"):
        log.info("=" * 60)
        log.info("STAGE 1.8 — LOG INGESTION / REPLAY SIMULATOR")
        log.info("=" * 60)
        from src.ingestion.log_replay import run_replay
        run_replay()

    elif command == "verify":
        log.info("=" * 60)
        log.info("MILESTONE 2 — VERIFICATION AGENT")
        log.info("=" * 60)
        from src.verification.verification_agent import run_verification
        run_verification()

    elif command == "score":
        log.info("=" * 60)
        log.info("MILESTONE 3 — CONFIDENCE SCORING ENGINE & PRIORITISATION MATRIX")
        log.info("=" * 60)
        from src.scoring.prioritisation_matrix import evaluate_prioritisation_matrix
        evaluate_prioritisation_matrix()

    elif command == "report":
        log.info("=" * 60)
        log.info("MILESTONE 3 — EVIDENCE REPORT GENERATOR (JSON + PDF)")
        log.info("=" * 60)
        from src.reporting.sample_reports import generate_sample_reports
        generate_sample_reports()

    elif command == "serve":
        log.info("=" * 60)
        log.info("MILESTONE 4 — FASTAPI BACKEND SERVER")
        log.info("=" * 60)
        import uvicorn
        from src.config.config import API_HOST, API_PORT
        log.info(f"Starting server on http://{API_HOST}:{API_PORT}")
        uvicorn.run("src.api.main:app", host=API_HOST, port=API_PORT, reload=True)

    elif command == "pipeline":
        log.info("=" * 60)
        log.info("PIPELINE ORCHESTRATOR — END-TO-END FLOW")
        log.info("=" * 60)
        print("Pipeline orchestrator: To be invoked in Milestone 3/5.")

    elif command == "evaluate-all":
        log.info("=" * 60)
        log.info("MILESTONE 5 — CONSOLIDATED FULL EVALUATION")
        log.info("=" * 60)
        print("Consolidated evaluation: To be invoked in Milestone 5.")

    else:
        log.error(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TRUST-SOC Unified CLI (synopsis-compliant)",
        epilog="Example: python run.py explore"
    )
    # Support positional command or --stage for backward compatibility
    parser.add_argument(
        "subcommand",
        nargs="?",
        default=None,
        choices=SUBCOMMANDS,
        help="Subcommand to execute (e.g., explore, preprocess, train, evaluate, etc.)"
    )
    parser.add_argument(
        "--stage",
        choices=SUBCOMMANDS,
        default=None,
        help="Alternative flag for specifying the subcommand"
    )

    args = parser.parse_args()
    cmd = args.subcommand or args.stage or "explore"
    log.info(f"Executing TRUST-SOC command: {cmd}")
    run_command(cmd)
    log.info("Command completed.")
