"""
Detection Agent — Evaluation
==============================
Runs the trained model against the held-out test set and
saves all metrics, confusion matrix, and classification report.

False Positive Rate (FPR) Calculation
--------------------------------------
For a multi-class problem we compute per-class FPR using
the one-vs-rest approach:

    FPR_class_i = FP_i / (FP_i + TN_i)

where FP_i = samples of other classes predicted as class i
      TN_i = samples of other classes correctly predicted as NOT class i

We then report:
    - per-class FPR
    - macro-average FPR (unweighted mean across classes)
    - weighted-average FPR (weighted by class support)

This baseline FPR is the TARGET for the Verification Agent to reduce.
"""

import sys
import json
import logging
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.config.config import (
    METRICS_DIR, CM_DIR, REPORTS_DIR,
    PROCESSED_X_TEST, PROCESSED_Y_TEST,
)
from src.detection.model import DetectionAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("TRUST-SOC.predict")


# ─────────────────────────────────────────────────────────────────
# FPR Calculation (one-vs-rest, multiclass)
# ─────────────────────────────────────────────────────────────────

def compute_fpr_multiclass(y_true, y_pred, n_classes):
    """
    Per-class FPR via one-vs-rest confusion matrix.
    Returns (per_class_fpr, macro_fpr, weighted_fpr).
    """
    cm = confusion_matrix(y_true, y_pred, labels=list(range(n_classes)))
    fp = cm.sum(axis=0) - np.diag(cm)   # column sum minus TP
    fn = cm.sum(axis=1) - np.diag(cm)
    tp = np.diag(cm)
    tn = cm.sum() - (fp + fn + tp)

    per_class_fpr = np.where((fp + tn) > 0, fp / (fp + tn), 0.0)
    support       = cm.sum(axis=1)

    macro_fpr    = float(np.mean(per_class_fpr))
    weighted_fpr = float(np.average(per_class_fpr, weights=support))

    return per_class_fpr, macro_fpr, weighted_fpr


# ─────────────────────────────────────────────────────────────────
# Plot confusion matrix
# ─────────────────────────────────────────────────────────────────

def plot_confusion_matrix(cm, class_names, save_path):
    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=class_names, yticklabels=class_names,
        ax=ax, linewidths=0.5,
    )
    ax.set_xlabel("Predicted Label", fontsize=12)
    ax.set_ylabel("True Label", fontsize=12)
    ax.set_title("TRUST-SOC Detection Agent — Confusion Matrix", fontsize=13)
    plt.tight_layout()
    fig.savefig(save_path, dpi=150)
    plt.close(fig)
    log.info(f"Confusion matrix saved → {save_path}")


# ─────────────────────────────────────────────────────────────────
# Main evaluation
# ─────────────────────────────────────────────────────────────────

def evaluate():
    log.info("=" * 60)
    log.info("TRUST-SOC  |  Detection Agent — Evaluation (Baseline)")
    log.info("=" * 60)

    # Load model
    agent = DetectionAgent.load()
    encoder = agent.encoder
    class_names = list(encoder.classes_)
    n_classes   = len(class_names)

    # Load test data
    X_test = pd.read_parquet(PROCESSED_X_TEST)
    y_test = pd.read_parquet(PROCESSED_Y_TEST)["label"].values
    log.info(f"Test set: {X_test.shape[0]:,} samples, {n_classes} classes")

    # Predict
    y_pred = agent.predict(X_test)

    # ── Core metrics ─────────────────────────────────────────────
    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall    = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1        = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    per_class_fpr, macro_fpr, weighted_fpr = compute_fpr_multiclass(y_test, y_pred, n_classes)

    log.info(f"\n  {'Accuracy':.<30} {accuracy:.4f}")
    log.info(f"  {'Precision (weighted)':.<30} {precision:.4f}")
    log.info(f"  {'Recall (weighted)':.<30} {recall:.4f}")
    log.info(f"  {'F1 (weighted)':.<30} {f1:.4f}")
    log.info(f"  {'FPR (macro avg)':.<30} {macro_fpr:.4f}")
    log.info(f"  {'FPR (weighted avg)':.<30} {weighted_fpr:.4f}")
    log.info("\n  Per-class FPR:")
    for cls, fpr in zip(class_names, per_class_fpr):
        log.info(f"    {cls:<25} {fpr:.4f}")

    # ── Classification report ─────────────────────────────────────
    report_str = classification_report(
        y_test, y_pred,
        target_names=class_names,
        zero_division=0,
    )
    log.info(f"\nClassification Report:\n{report_str}")

    # ── Confusion matrix ──────────────────────────────────────────
    cm = confusion_matrix(y_test, y_pred)

    # ── Save results ──────────────────────────────────────────────
    for d in [METRICS_DIR, CM_DIR, REPORTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    # Per-class metrics from classification_report
    report_dict = classification_report(
        y_test, y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )

    # Build metrics JSON
    metrics = {
        "model":              "Random Forest (baseline)",
        "accuracy":           round(accuracy, 4),
        "precision_weighted": round(precision, 4),
        "recall_weighted":    round(recall, 4),
        "f1_weighted":        round(f1, 4),
        "fpr_macro":          round(macro_fpr, 4),
        "fpr_weighted":       round(weighted_fpr, 4),
        "fpr_per_class":      {
            cls: round(float(fpr), 4)
            for cls, fpr in zip(class_names, per_class_fpr)
        },
        "per_class_metrics":  {
            cls: {k: round(v, 4) for k, v in report_dict[cls].items()}
            for cls in class_names
        },
        "note_fpr": (
            "FPR calculated one-vs-rest. "
            "FP_i = samples of other classes predicted as class i. "
            "Macro = unweighted mean. Weighted = support-weighted mean."
        ),
    }

    json_path = METRICS_DIR / "detection_baseline.json"
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=2)
    log.info(f"Metrics JSON saved → {json_path}")

    # CSV
    csv_path = METRICS_DIR / "detection_baseline.csv"
    pd.DataFrame([{
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1,
        "fpr_macro": macro_fpr, "fpr_weighted": weighted_fpr,
    }]).to_csv(csv_path, index=False)

    # Classification report text
    txt_path = REPORTS_DIR / "classification_report.txt"
    with open(txt_path, "w") as f:
        f.write("TRUST-SOC Detection Agent — Baseline Classification Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(report_str)
        f.write("\n\nFPR (per class):\n")
        for cls, fpr in zip(class_names, per_class_fpr):
            f.write(f"  {cls:<25} {fpr:.4f}\n")
        f.write(f"\nFPR macro avg:    {macro_fpr:.4f}\n")
        f.write(f"FPR weighted avg: {weighted_fpr:.4f}\n")

    # Confusion matrix plot
    cm_path = CM_DIR / "confusion_matrix.png"
    plot_confusion_matrix(cm, class_names, cm_path)

    log.info("=" * 60)
    log.info("Evaluation COMPLETE.")
    log.info("=" * 60)
    return metrics


if __name__ == "__main__":
    evaluate()
