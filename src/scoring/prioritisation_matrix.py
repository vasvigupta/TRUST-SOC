"""
Alert Prioritisation Matrix (Stage 3.2)
=======================================
Evaluates the 3x3 operational prioritisation matrix combining Detection probability (p_d)
and Verification decision (CONFIRM / REDUCE / REJECT) across the held-out test split.

Outputs:
  - results/metrics/prioritisation_matrix.json
  - results/reports/prioritisation_matrix.md
  - results/metrics/prioritisation_matrix.png
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib

from src.config.config import (
    PROCESSED_X_TEST,
    PROCESSED_X_TEST_RAW,
    PROCESSED_TEST_FLOWS,
    FEATURE_NAMES_PATH,
    VERIFICATION_WEIGHTS,
    P_V_CONFIRM_THRESHOLD,
    P_V_REDUCE_THRESHOLD,
    STRONG_CONTRADICTION_THRESHOLD,
    REPORTS_DIR,
    METRICS_DIR,
)
from src.config.theme import THEME, apply_matplotlib_theme
from src.verification.verification_agent import VerificationAgent
from src.scoring.confidence_scorer import ConfidenceScoringEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("TRUST-SOC.prioritisation_matrix")


def evaluate_prioritisation_matrix(
    test_preds_path: Path = Path("results/predictions/test_predictions.joblib"),
    test_meta_path: Path = PROCESSED_TEST_FLOWS,
    test_raw_path: Path = PROCESSED_X_TEST_RAW,
    test_scaled_path: Path = PROCESSED_X_TEST,
    feature_names_path: Path = FEATURE_NAMES_PATH,
) -> Dict[str, Any]:
    """Computes the 3x3 prioritisation matrix on test alerts."""
    apply_matplotlib_theme(plt)

    log.info("Loading test data for prioritisation matrix...")
    test_preds = joblib.load(test_preds_path)
    test_meta = joblib.load(test_meta_path)
    X_test_raw = joblib.load(test_raw_path)
    X_test = joblib.load(test_scaled_path)
    feat_names = joblib.load(feature_names_path)

    y_true = test_preds["y_true"]
    y_pred = test_preds["y_pred"]
    y_proba = test_preds["y_proba"]
    classes = test_preds["classes"]

    alert_mask = (y_pred != 0)
    alert_indices = np.where(alert_mask)[0]
    n_alerts = len(alert_indices)

    agent = VerificationAgent(
        weights=VERIFICATION_WEIGHTS,
        confirm_thresh=P_V_CONFIRM_THRESHOLD,
        reduce_thresh=P_V_REDUCE_THRESHOLD,
        strong_contra_thresh=STRONG_CONTRADICTION_THRESHOLD,
    )
    agent.behavioural_verifier.reset_windows()

    scorer = ConfidenceScoringEngine()

    meta_dicts = test_meta.iloc[alert_indices].to_dict("records")
    feat_dicts = X_test_raw.iloc[alert_indices].to_dict("records")
    X_alerts = X_test[alert_indices]
    y_true_alerts = y_true[alert_indices]
    y_pred_alerts = y_pred[alert_indices]

    df_scores = agent.statistical_verifier.model.decision_function(X_alerts)
    denom = agent.statistical_verifier.q95 - agent.statistical_verifier.q01
    s_scores = np.clip((agent.statistical_verifier.q95 - df_scores) / denom, 0.0, 1.0)

    log.info(f"Processing {n_alerts} test alerts through verification and confidence scoring...")
    matrix = {
        "CONFIRM": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "REDUCE":  {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "REJECT":  {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }
    matrix_breakdown = {
        "CONFIRM": {"HIGH": {"attack": 0, "false_alarm": 0}, "MEDIUM": {"attack": 0, "false_alarm": 0}, "LOW": {"attack": 0, "false_alarm": 0}},
        "REDUCE":  {"HIGH": {"attack": 0, "false_alarm": 0}, "MEDIUM": {"attack": 0, "false_alarm": 0}, "LOW": {"attack": 0, "false_alarm": 0}},
        "REJECT":  {"HIGH": {"attack": 0, "false_alarm": 0}, "MEDIUM": {"attack": 0, "false_alarm": 0}, "LOW": {"attack": 0, "false_alarm": 0}},
    }
    band_distribution = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for i in range(n_alerts):
        p_c = str(classes[y_pred_alerts[i]])
        m = meta_dicts[i]
        f = feat_dicts[i]
        vec = X_alerts[i]
        s_val = float(s_scores[i])

        r_sig = agent.rule_verifier.verify_flow(p_c, m, f)
        s_sig = {"score": s_val, "strongly_contradictory": s_val < STRONG_CONTRADICTION_THRESHOLD, "details": {}}
        b_sig = agent.behavioural_verifier.verify_flow(m, f, update_window=True)
        e_sig = agent.explanation_verifier.verify_explanation(p_c, scaled_vector=vec, feature_names=feat_names)

        from src.verification.decision import compute_verification_decision
        dec = compute_verification_decision(r_sig, s_sig, b_sig, e_sig, weights=agent.weights)
        dec_label = dec["decision"]
        p_v = dec["p_v"]
        r_corr = dec["signals"]["rule"]["score"]

        # Detection probability
        p_d = float(y_proba[alert_indices[i], y_pred_alerts[i]])
        p_d_level = "HIGH" if p_d >= 0.80 else ("MEDIUM" if p_d >= 0.50 else "LOW")

        # Confidence Scoring
        sc_block = scorer.compute_confidence(p_d, p_v, r_corr, verification_decision=dec_label)
        band_distribution[sc_block["band"]] += 1

        is_attack = bool(y_true_alerts[i] != 0)
        target_key = "attack" if is_attack else "false_alarm"

        matrix[dec_label][p_d_level] += 1
        matrix_breakdown[dec_label][p_d_level][target_key] += 1

    results = {
        "total_alerts": n_alerts,
        "matrix": matrix,
        "matrix_breakdown": matrix_breakdown,
        "band_distribution": band_distribution,
    }

    # Save JSON
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    out_json = METRICS_DIR / "prioritisation_matrix.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    log.info(f"Saved prioritisation matrix to {out_json}")

    # Generate Plot
    _plot_matrix(matrix, METRICS_DIR / "prioritisation_matrix.png")

    # Generate Markdown Report
    _write_matrix_markdown(results, REPORTS_DIR / "prioritisation_matrix.md")

    return results


def _plot_matrix(matrix: Dict[str, Dict[str, int]], save_path: Path):
    """Generates pure Matplotlib light-theme heatmap/table visualization."""
    apply_matplotlib_theme(plt)

    rows = ["CONFIRM", "REDUCE", "REJECT"]
    cols = ["HIGH (p_d>=0.80)", "MEDIUM (0.50<=p_d<0.80)", "LOW (p_d<0.50)"]
    col_keys = ["HIGH", "MEDIUM", "LOW"]

    grid = np.array([[matrix[r][c] for c in col_keys] for r in rows])

    fig, ax = plt.subplots(figsize=(8, 6), facecolor=THEME["bg"])
    ax.set_facecolor(THEME["surface"])

    cax = ax.imshow(grid, cmap="Blues", interpolation="nearest", alpha=0.85)

    ax.set_xticks(np.arange(len(cols)))
    ax.set_yticks(np.arange(len(rows)))
    ax.set_xticklabels(cols, fontsize=10, fontweight="bold", color=THEME["text"])
    ax.set_yticklabels(rows, fontsize=11, fontweight="bold", color=THEME["text"])

    ax.set_xlabel("Detection Agent Probability ($p_d$)", fontsize=11, fontweight="bold", color=THEME["primary"], labelpad=10)
    ax.set_ylabel("Verification Agent Verdict", fontsize=11, fontweight="bold", color=THEME["primary"], labelpad=10)
    ax.set_title("TRUST-SOC Alert Prioritisation Matrix", fontsize=13, fontweight="bold", color=THEME["primary"], pad=14)

    # Action annotations per cell
    action_labels = [
        ["Urgent Auto-Escalate", "High Priority Queue", "Standard Review"],
        ["Medium Priority Review", "Standard Review", "Low Priority / Log"],
        ["Dropped False Alarm", "Dropped False Alarm", "Dropped False Alarm"],
    ]

    for i in range(len(rows)):
        for j in range(len(cols)):
            cnt = grid[i, j]
            label = action_labels[i][j]
            ax.text(
                j, i, f"{cnt:,}\n({label})",
                ha="center", va="center",
                fontsize=9.5, fontweight="bold",
                color=THEME["primary"] if cnt < grid.max()*0.6 else "white"
            )

    plt.tight_layout()
    save_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(save_path, dpi=300, bbox_inches="tight", facecolor=THEME["bg"])
    plt.close()
    log.info(f"Saved prioritisation matrix plot to {save_path}")


def _write_matrix_markdown(results: Dict[str, Any], output_path: Path):
    """Writes detailed Markdown report for Prioritisation Matrix."""
    m = results["matrix"]
    mb = results["matrix_breakdown"]
    bd = results["band_distribution"]
    total = results["total_alerts"]

    lines = [
        "# TRUST-SOC Alert Prioritisation Matrix Report",
        "",
        "## 1. Operational 3x3 Matrix Breakdown",
        "",
        "| Verification Decision | Detection $p_d$ HIGH (>=0.80) | Detection $p_d$ MEDIUM (0.50-0.80) | Detection $p_d$ LOW (<0.50) | Operational Triage Action |",
        "|:---|:---:|:---:|:---:|:---|",
        f"| **CONFIRM** | **{m['CONFIRM']['HIGH']:,}** ({mb['CONFIRM']['HIGH']['attack']} attacks / {mb['CONFIRM']['HIGH']['false_alarm']} FAs) | **{m['CONFIRM']['MEDIUM']:,}** | **{m['CONFIRM']['LOW']:,}** | **Auto-Escalate** / High Priority Queue |",
        f"| **REDUCE** | **{m['REDUCE']['HIGH']:,}** ({mb['REDUCE']['HIGH']['attack']} attacks / {mb['REDUCE']['HIGH']['false_alarm']} FAs) | **{m['REDUCE']['MEDIUM']:,}** | **{m['REDUCE']['LOW']:,}** | **Suspicious Review** / Standard Queue |",
        f"| **REJECT** | **{m['REJECT']['HIGH']:,}** ({mb['REJECT']['HIGH']['attack']} attacks / {mb['REJECT']['HIGH']['false_alarm']} FAs) | **{m['REJECT']['MEDIUM']:,}** | **{m['REJECT']['LOW']:,}** | **Dropped False Alarm** (Audit Logged) |",
        "",
        "## 2. Confidence Band Distribution",
        "",
        f"- **HIGH Band ($C \\ge 0.80$):** {bd['HIGH']:,} alerts ({bd['HIGH']/total*100:.1f}%) — Auto-escalated for immediate SOC response.",
        f"- **MEDIUM Band ($0.50 \\le C < 0.80$):** {bd['MEDIUM']:,} alerts ({bd['MEDIUM']/total*100:.1f}%) — Queued for senior analyst investigation.",
        f"- **LOW Band ($C < 0.50$):** {bd['LOW']:,} alerts ({bd['LOW']/total*100:.1f}%) — Suppressed / Logged without analyst interruption.",
        "",
        "## 3. Operational Impact",
        "",
        "- High-confidence alerts are auto-escalated with verifiable evidence.",
        "- False alarms flagged by independent verification are reclassified as REJECT and suppressed, dramatically reducing alert fatigue.",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log.info(f"Wrote prioritisation matrix report to {output_path}")


if __name__ == "__main__":
    evaluate_prioritisation_matrix()
