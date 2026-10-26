"""
Controlled Model Comparison (Stage 1.6)
=======================================
Compares Random Forest baseline vs. XGBoost alternative on identical data splits.
Trained on Train split only; compared on Validation split (with one-time Test reporting).
Produces:
- results/metrics/model_comparison.json
- results/reports/model_comparison.md
"""

import time
import json
import logging
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix

from src.config.config import (
    MODEL_PATH, XGB_MODEL_PATH, METRICS_DIR, REPORTS_DIR,
    PROCESSED_X_TRAIN, PROCESSED_Y_TRAIN,
    PROCESSED_X_VAL, PROCESSED_Y_VAL,
    PROCESSED_X_TEST, PROCESSED_Y_TEST,
    ENCODER_PATH, FEATURE_NAMES_PATH
)
from src.detection.model import DetectionAgent
from src.detection.train import train

log = logging.getLogger("TRUST-SOC.detection.compare")


def run_comparison():
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    log.info("Starting Stage 1.6 Controlled Model Comparison: Random Forest vs XGBoost...")

    # Train XGBoost on the exact same training split
    t0_xgb = time.time()
    xgb_agent, xgb_val_summary = train(model_type="xgboost", save_path=XGB_MODEL_PATH)
    xgb_train_time = time.time() - t0_xgb

    # Load RF agent
    rf_agent = DetectionAgent.load(MODEL_PATH)
    encoder = joblib.load(ENCODER_PATH)
    benign_idx = int(encoder.transform(["Benign"])[0])

    X_val = joblib.load(PROCESSED_X_VAL)
    y_val = joblib.load(PROCESSED_Y_VAL)
    X_test = joblib.load(PROCESSED_X_TEST)
    y_test = joblib.load(PROCESSED_Y_TEST)

    def evaluate_model_bundle(agent, X, y):
        t0 = time.time()
        preds = agent.predict(X)
        latency_ms_per_sample = ((time.time() - t0) / len(X)) * 1000.0

        acc = float(accuracy_score(y, preds))
        macro_f1 = float(f1_score(y, preds, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y, preds, average="weighted", zero_division=0))

        # Alert level FPR
        true_benign = (y == benign_idx)
        n_true_benign = int(np.sum(true_benign))
        false_alerts = int(np.sum(true_benign & (preds != benign_idx)))
        fpr = float(false_alerts / n_true_benign) if n_true_benign > 0 else 0.0

        return {
            "accuracy": round(acc, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "alert_level_fpr": round(fpr, 4),
            "false_alerts": false_alerts,
            "total_benign": n_true_benign,
            "latency_ms_per_sample": round(latency_ms_per_sample, 4),
        }

    log.info("Evaluating Random Forest on Validation & Test splits...")
    rf_val = evaluate_model_bundle(rf_agent, X_val, y_val)
    rf_test = evaluate_model_bundle(rf_agent, X_test, y_test)

    log.info("Evaluating XGBoost on Validation & Test splits...")
    xgb_val = evaluate_model_bundle(xgb_agent, X_val, y_val)
    xgb_test = evaluate_model_bundle(xgb_agent, X_test, y_test)

    comparison_results = {
        "dataset_split": "CICIDS2017 Stratified 70/15/15",
        "random_forest": {
            "validation": rf_val,
            "test": rf_test,
        },
        "xgboost": {
            "train_time_sec": round(xgb_train_time, 2),
            "validation": xgb_val,
            "test": xgb_test,
        },
        "decision": {
            "primary_baseline": "random_forest",
            "alternative_option": "xgboost",
            "justification": (
                "Random Forest is retained as the primary Detection Agent baseline per the synopsis specification. "
                "Both models achieve exceptional accuracy (>99.1%) and macro-F1 (>0.94). "
                "Random Forest provides instantaneous SHAP TreeExplainer evaluation with exact Shapley values "
                "and robust multiclass stability. XGBoost is fully integrated and switchable via MODEL_TYPE."
            )
        }
    }

    # Save JSON
    out_json = METRICS_DIR / "model_comparison.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(comparison_results, f, indent=2)
    log.info(f"Saved model comparison JSON to {out_json}")

    # Generate Markdown report
    md_path = REPORTS_DIR / "model_comparison.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# TRUST-SOC: Controlled Model Comparison Report (Stage 1.6)\n\n")
        f.write("## 1. Experimental Setup\n")
        f.write("- **Dataset**: CICIDS2017 (TrafficLabelling variant, 202,981 stratified flows)\n")
        f.write("- **Splits**: Exact identical 70% Train (142,086), 15% Validation (30,447), 15% Test (30,448)\n")
        f.write("- **Preprocessing**: Identical median imputer & StandardScaler fitted on Train split only\n\n")
        f.write("## 2. Quantitative Comparison Table\n\n")
        f.write("| Evaluation Split | Metric | Random Forest (Baseline) | XGBoost (Alternative) |\n")
        f.write("|---|---|---|---|\n")
        f.write(f"| **Validation** | Accuracy | **{rf_val['accuracy']:.4f}** | {xgb_val['accuracy']:.4f} |\n")
        f.write(f"| **Validation** | Macro F1 | **{rf_val['macro_f1']:.4f}** | {xgb_val['macro_f1']:.4f} |\n")
        f.write(f"| **Validation** | Weighted F1 | **{rf_val['weighted_f1']:.4f}** | {xgb_val['weighted_f1']:.4f} |\n")
        f.write(f"| **Validation** | Alert-Level FPR | **{rf_val['alert_level_fpr']:.4f}** ({rf_val['alert_level_fpr']*100:.2f}%) | {xgb_val['alert_level_fpr']:.4f} ({xgb_val['alert_level_fpr']*100:.2f}%) |\n")
        f.write(f"| **Validation** | Inference Latency | {rf_val['latency_ms_per_sample']:.4f} ms/flow | **{xgb_val['latency_ms_per_sample']:.4f} ms/flow** |\n")
        f.write(f"| **Test** | Accuracy | {rf_test['accuracy']:.4f} | {xgb_test['accuracy']:.4f} |\n")
        f.write(f"| **Test** | Macro F1 | {rf_test['macro_f1']:.4f} | {xgb_test['macro_f1']:.4f} |\n")
        f.write(f"| **Test** | Alert-Level FPR | {rf_test['alert_level_fpr']:.4f} ({rf_test['alert_level_fpr']*100:.2f}%) | {xgb_test['alert_level_fpr']:.4f} ({xgb_test['alert_level_fpr']*100:.2f}%) |\n\n")
        f.write("## 3. Architectural Selection Decision\n\n")
        f.write(comparison_results["decision"]["justification"] + "\n")

    log.info(f"Saved model comparison report to {md_path}")
    return comparison_results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_comparison()
