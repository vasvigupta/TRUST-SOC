"""
Detection Agent Baseline Evaluation (Stage 1.5)
================================================
Evaluates the Detection Agent on the held-out test split.
Calculates:
- Primary Alert-Level False Positive Rate (FPR) as defined in Section 4.5:
      FPR = (# true Benign flows raised as alerts) / (# total true Benign flows)
      where ALERT = any flow classified as non-Benign.
- Multiclass one-vs-rest FPR, Precision, Recall, and F1 per class.
- Macro and weighted metrics.
- Saves confusion matrix plot (pure Matplotlib, light theme).
- Saves predictions on validation and test splits for Milestone 2 consumption.
"""

import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix
)

from src.config.config import (
    MODEL_PATH, METRICS_DIR, CM_DIR, REPORTS_DIR,
    PROCESSED_X_VAL, PROCESSED_Y_VAL,
    PROCESSED_X_TEST, PROCESSED_Y_TEST,
    ENCODER_PATH, FEATURE_NAMES_PATH,
    PROJECT_CLASSES
)
from src.config.theme import THEME, apply_matplotlib_theme
from src.detection.model import DetectionAgent

log = logging.getLogger("TRUST-SOC.detection.evaluate")


def evaluate(model_path: Path = MODEL_PATH, model_name: str = "Detection Agent Baseline"):
    """
    Runs full evaluation on the held-out test set and saves baseline metrics.
    """
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    CM_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (METRICS_DIR.parent / "predictions").mkdir(parents=True, exist_ok=True)

    agent = DetectionAgent.load(model_path)
    encoder = joblib.load(ENCODER_PATH)

    log.info("Loading test and validation splits...")
    X_test = joblib.load(PROCESSED_X_TEST)
    y_test = joblib.load(PROCESSED_Y_TEST)
    X_val  = joblib.load(PROCESSED_X_VAL)
    y_val  = joblib.load(PROCESSED_Y_VAL)

    classes = list(encoder.classes_)
    benign_idx = int(encoder.transform(["Benign"])[0])

    # 1. Generate predictions and probabilities on Test split
    log.info(f"Generating test predictions on {len(X_test):,} flows...")
    y_test_pred = agent.predict(X_test)
    y_test_proba = agent.predict_proba(X_test)

    # 2. Compute Alert-Level Binary FPR (Section 4.5 REFERENCE METRIC)
    # ALERT = any flow predicted as non-Benign
    true_benign_mask = (y_test == benign_idx)
    total_true_benign = int(np.sum(true_benign_mask))

    # False alerts = true benign flows classified as an attack class
    benign_false_alerts = int(np.sum(true_benign_mask & (y_test_pred != benign_idx)))
    alert_level_fpr = float(benign_false_alerts / total_true_benign) if total_true_benign > 0 else 0.0

    log.info("=" * 65)
    log.info(f"PRIMARY REFERENCE METRIC — ALERT-LEVEL FPR BEFORE VERIFICATION:")
    log.info(f"  FPR_before = {benign_false_alerts:,} / {total_true_benign:,} = {alert_level_fpr:.4f} ({alert_level_fpr*100:.2f}%)")
    log.info("=" * 65)

    # 3. Overall Multiclass Metrics
    accuracy = float(accuracy_score(y_test, y_test_pred))
    macro_precision = float(precision_score(y_test, y_test_pred, average="macro", zero_division=0))
    macro_recall = float(recall_score(y_test, y_test_pred, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_test, y_test_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_test_pred, average="weighted", zero_division=0))

    # 4. Per-Class One-vs-Rest Confusion Matrix & Per-Class FPR
    cm = confusion_matrix(y_test, y_test_pred, labels=list(range(len(classes))))
    per_class_metrics = {}

    fp_sum = 0
    tn_sum = 0
    per_class_fprs = []

    for i, cls_name in enumerate(classes):
        tp_i = int(cm[i, i])
        fn_i = int(np.sum(cm[i, :]) - tp_i)
        fp_i = int(np.sum(cm[:, i]) - tp_i)
        tn_i = int(np.sum(cm) - (tp_i + fn_i + fp_i))

        prec_i = float(tp_i / (tp_i + fp_i)) if (tp_i + fp_i) > 0 else 0.0
        rec_i  = float(tp_i / (tp_i + fn_i)) if (tp_i + fn_i) > 0 else 0.0
        f1_i   = float(2 * prec_i * rec_i / (prec_i + rec_i)) if (prec_i + rec_i) > 0 else 0.0
        fpr_i  = float(fp_i / (fp_i + tn_i)) if (fp_i + tn_i) > 0 else 0.0

        per_class_fprs.append(fpr_i)
        fp_sum += fp_i
        tn_sum += tn_i

        per_class_metrics[cls_name] = {
            "support": int(np.sum(cm[i, :])),
            "precision": round(prec_i, 4),
            "recall": round(rec_i, 4),
            "f1_score": round(f1_i, 4),
            "fpr_one_vs_rest": round(fpr_i, 4),
            "tp": tp_i,
            "fp": fp_i,
            "tn": tn_i,
            "fn": fn_i,
        }

    macro_ovr_fpr = float(np.mean(per_class_fprs))

    # 5. Format and Save Baseline Results
    baseline_metrics = {
        "model_name": model_name,
        "model_type": agent.model_type,
        "test_samples": len(y_test),
        "primary_alert_level_fpr": {
            "total_true_benign": total_true_benign,
            "benign_flows_falsely_alerted": benign_false_alerts,
            "alert_level_fpr_before_verification": round(alert_level_fpr, 4),
            "alert_level_fpr_percentage": f"{alert_level_fpr*100:.2f}%",
            "formula": "FP_benign / (FP_benign + TN_benign) over all non-benign predictions"
        },
        "multiclass_metrics": {
            "accuracy": round(accuracy, 4),
            "macro_precision": round(macro_precision, 4),
            "macro_recall": round(macro_recall, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "macro_one_vs_rest_fpr": round(macro_ovr_fpr, 4),
        },
        "per_class": per_class_metrics,
        "confusion_matrix": cm.tolist(),
        "classes": classes
    }

    # Save JSON
    json_path = METRICS_DIR / "detection_baseline.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(baseline_metrics, f, indent=2)
    log.info(f"Saved baseline metrics JSON to {json_path}")

    # Save CSV summary
    csv_rows = []
    for cls_name, m in per_class_metrics.items():
        csv_rows.append({
            "class": cls_name,
            "support": m["support"],
            "precision": m["precision"],
            "recall": m["recall"],
            "f1_score": m["f1_score"],
            "fpr_ovr": m["fpr_one_vs_rest"],
        })
    csv_df = pd.DataFrame(csv_rows)
    csv_path = METRICS_DIR / "detection_baseline.csv"
    csv_df.to_csv(csv_path, index=False)
    log.info(f"Saved baseline metrics CSV to {csv_path}")

    # Save Classification Report text
    clf_report = classification_report(y_test, y_test_pred, target_names=classes, digits=4, zero_division=0)
    report_text_path = REPORTS_DIR / "classification_report.txt"
    with open(report_text_path, "w", encoding="utf-8") as f:
        f.write("=" * 65 + "\n")
        f.write("TRUST-SOC DETECTION AGENT BASELINE CLASSIFICATION REPORT\n")
        f.write("=" * 65 + "\n\n")
        f.write(f"Model: {agent.model_type}\n")
        f.write(f"Test Set Size: {len(y_test):,} flows\n\n")
        f.write(f"PRIMARY METRIC — Alert-Level FPR: {alert_level_fpr:.4f} ({alert_level_fpr*100:.2f}%)\n")
        f.write(f"Overall Accuracy:                 {accuracy:.4f}\n")
        f.write(f"Macro F1 Score:                   {macro_f1:.4f}\n")
        f.write(f"Weighted F1 Score:                {weighted_f1:.4f}\n\n")
        f.write(clf_report + "\n")
    log.info(f"Saved classification report to {report_text_path}")

    # 6. Plot Confusion Matrix (Pure Matplotlib, Light Theme, Section 3 tokens)
    cm_path = CM_DIR / "confusion_matrix.png"
    plot_light_confusion_matrix(cm, classes, cm_path)

    # 7. Save Validation and Test Predictions for Milestone 2 Consumption
    log.info("Generating and saving validation split predictions for Milestone 2...")
    y_val_pred = agent.predict(X_val)
    y_val_proba = agent.predict_proba(X_val)

    val_preds_bundle = {
        "y_true": y_val,
        "y_pred": y_val_pred,
        "y_proba": y_val_proba,
        "classes": classes,
    }
    test_preds_bundle = {
        "y_true": y_test,
        "y_pred": y_test_pred,
        "y_proba": y_test_proba,
        "classes": classes,
    }
    joblib.dump(val_preds_bundle, METRICS_DIR.parent / "predictions" / "val_predictions.joblib", compress=3)
    joblib.dump(test_preds_bundle, METRICS_DIR.parent / "predictions" / "test_predictions.joblib", compress=3)
    log.info("Saved val_predictions.joblib and test_predictions.joblib for Milestone 2.")

    return baseline_metrics


def plot_light_confusion_matrix(cm: np.ndarray, classes: List[str], save_path: Path):
    """
    Renders an accessible, light-theme confusion matrix using pure Matplotlib.
    """
    apply_matplotlib_theme(plt)

    fig, ax = plt.subplots(figsize=(8.5, 7), facecolor=THEME["surface"])

    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    ax.set(
        xticks=np.arange(cm.shape[1]),
        yticks=np.arange(cm.shape[0]),
        xticklabels=classes,
        yticklabels=classes,
        title="Detection Agent Baseline — Confusion Matrix (Test Split)",
        ylabel="True Label (Ground Truth)",
        xlabel="Predicted Label"
    )

    plt.setp(ax.get_xticklabels(), rotation=30, ha="right", rotation_mode="anchor")

    # Annotate values inside matrix
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm[i, j]
            color = "#FFFFFF" if val > thresh else THEME["text"]
            ax.text(j, i, f"{val:,}", ha="center", va="center", color=color, fontsize=9, weight="bold")

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(THEME["border"])
    ax.spines["bottom"].set_color(THEME["border"])

    plt.tight_layout()
    fig.savefig(save_path, dpi=300, facecolor=THEME["surface"], bbox_inches="tight")
    plt.close(fig)
    log.info(f"Saved confusion matrix plot to {save_path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    evaluate()
