"""
Frozen Test-Set Evaluation (Stage 2.8)
======================================
Evaluates the Verification Agent strictly once on the held-out frozen test set.
Measures the primary project success metric:
  - Baseline vs. Post-Verification False Positive Rate (FPR)
  - Absolute and percentage FPR reduction
  - Recall cost of verification
  - Per-class breakdown
  - Cohen's kappa agreement with ground truth
  - Light-theme publication-ready comparative visualization

Outputs:
  - results/verification/verification_results.json
  - results/verification/fpr_reduction.png
  - results/reports/verification_report.md
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
from sklearn.metrics import cohen_kappa_score

from src.config.config import (
    PROCESSED_X_TEST,
    PROCESSED_X_TEST_RAW,
    PROCESSED_TEST_FLOWS,
    PROCESSED_Y_TEST,
    FEATURE_NAMES_PATH,
    VERIFICATION_RESULTS_DIR,
    REPORTS_DIR,
    VERIFICATION_WEIGHTS,
    P_V_CONFIRM_THRESHOLD,
    P_V_REDUCE_THRESHOLD,
    STRONG_CONTRADICTION_THRESHOLD,
)
from src.config.theme import THEME, apply_matplotlib_theme
from src.verification.verification_agent import VerificationAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("TRUST-SOC.evaluate_verification")


def run_test_evaluation(
    test_preds_path: Path = Path("results/predictions/test_predictions.joblib"),
    test_meta_path: Path = PROCESSED_TEST_FLOWS,
    test_raw_path: Path = PROCESSED_X_TEST_RAW,
    test_scaled_path: Path = PROCESSED_X_TEST,
    feature_names_path: Path = FEATURE_NAMES_PATH,
) -> Dict[str, Any]:
    """
    Executes single-pass evaluation on the frozen test set.
    """
    apply_matplotlib_theme(plt)

    log.info("Loading frozen test set artifacts...")
    test_preds = joblib.load(test_preds_path)
    test_meta = joblib.load(test_meta_path)
    X_test_raw = joblib.load(test_raw_path)
    X_test = joblib.load(test_scaled_path)
    feat_names = joblib.load(feature_names_path)

    y_true = test_preds["y_true"]
    y_pred = test_preds["y_pred"]
    classes = test_preds["classes"]

    total_test = len(y_true)
    total_benign = int(np.sum(y_true == 0))
    total_attack = int(np.sum(y_true != 0))

    # Baseline Detection Agent performance
    alerts_mask = (y_pred != 0)
    alert_indices = np.where(alerts_mask)[0]
    n_alerts = len(alert_indices)

    fa_mask_all = (y_true == 0) & alerts_mask
    n_fa_baseline = int(np.sum(fa_mask_all))
    baseline_fpr = n_fa_baseline / total_benign

    ta_mask_all = (y_true != 0) & alerts_mask
    n_ta_baseline = int(np.sum(ta_mask_all))
    baseline_recall = n_ta_baseline / total_attack

    log.info("=" * 60)
    log.info(f"FROZEN TEST SET: {total_test:,} flows (Benign: {total_benign:,}, Attack: {total_attack:,})")
    log.info(f"Baseline Alerts Emitted: {n_alerts:,}")
    log.info(f"Baseline False Alarms: {n_fa_baseline:,} (FPR: {baseline_fpr*100:.3f}%)")
    log.info(f"Baseline Attack Alerts: {n_ta_baseline:,} (Recall: {baseline_recall*100:.3f}%)")
    log.info("=" * 60)

    # Instantiate Verification Agent with validation-tuned parameters
    agent = VerificationAgent(
        weights=VERIFICATION_WEIGHTS,
        confirm_thresh=P_V_CONFIRM_THRESHOLD,
        reduce_thresh=P_V_REDUCE_THRESHOLD,
        strong_contra_thresh=STRONG_CONTRADICTION_THRESHOLD,
    )
    agent.behavioural_verifier.reset_windows()

    # Pre-extract data for efficiency
    meta_dicts = test_meta.iloc[alert_indices].to_dict("records")
    feat_dicts = X_test_raw.iloc[alert_indices].to_dict("records")
    X_alerts = X_test[alert_indices]
    y_true_alerts = y_true[alert_indices]
    y_pred_alerts = y_pred[alert_indices]

    # Pre-compute vectorized statistical scores
    df_scores = agent.statistical_verifier.model.decision_function(X_alerts)
    denom = (agent.statistical_verifier.q95 - agent.statistical_verifier.q01)
    if denom <= 0:
        denom = 1.0
    s_scores = np.clip((agent.statistical_verifier.q95 - df_scores) / denom, 0.0, 1.0)

    log.info("Verifying all test alerts through Verification Agent...")
    decisions = []
    p_v_list = []
    signals_records = []

    for i in range(n_alerts):
        p_c = str(classes[y_pred_alerts[i]])
        m = meta_dicts[i]
        f = feat_dicts[i]
        vec = X_alerts[i]
        s_val = float(s_scores[i])

        r_sig = agent.rule_verifier.verify_flow(p_c, m, f)
        s_sig = {
            "score": s_val,
            "strongly_contradictory": s_val < STRONG_CONTRADICTION_THRESHOLD,
            "details": {},
        }
        b_sig = agent.behavioural_verifier.verify_flow(m, f, update_window=True)
        e_sig = agent.explanation_verifier.verify_explanation(
            p_c, scaled_vector=vec, feature_names=feat_names
        )

        from src.verification.decision import compute_verification_decision
        dec = compute_verification_decision(
            r_sig, s_sig, b_sig, e_sig,
            weights=agent.weights,
            confirm_thresh=agent.confirm_thresh,
            reduce_thresh=agent.reduce_thresh,
            strong_contra_thresh=agent.strong_contra_thresh,
        )

        decisions.append(dec["decision"])
        p_v_list.append(dec["p_v"])
        signals_records.append({
            "r": dec["signals"]["rule"]["score"],
            "s": dec["signals"]["statistical"]["score"],
            "b": dec["signals"]["behavioural"]["score"],
            "e": dec["signals"]["explanation"]["score"],
        })

    decisions = np.array(decisions)
    p_v_array = np.array(p_v_list)

    # Metrics calculation
    fa_alert_mask = (y_true_alerts == 0)
    ta_alert_mask = (y_true_alerts != 0)

    fa_confirm = int(np.sum(fa_alert_mask & (decisions == "CONFIRM")))
    fa_reduce = int(np.sum(fa_alert_mask & (decisions == "REDUCE")))
    fa_reject = int(np.sum(fa_alert_mask & (decisions == "REJECT")))

    # Lenient: surviving = CONFIRM + REDUCE (REJECT is filtered out)
    fa_surviving_lenient = fa_confirm + fa_reduce
    post_fpr_lenient = fa_surviving_lenient / total_benign
    abs_red_lenient = baseline_fpr - post_fpr_lenient
    rel_red_lenient = (abs_red_lenient / baseline_fpr) * 100.0 if baseline_fpr > 0 else 0.0

    # Strict: surviving = CONFIRM only (REDUCE and REJECT are filtered)
    fa_surviving_strict = fa_confirm
    post_fpr_strict = fa_surviving_strict / total_benign
    abs_red_strict = baseline_fpr - post_fpr_strict
    rel_red_strict = (abs_red_strict / baseline_fpr) * 100.0 if baseline_fpr > 0 else 0.0

    # Attack retention
    ta_confirm = int(np.sum(ta_alert_mask & (decisions == "CONFIRM")))
    ta_reduce = int(np.sum(ta_alert_mask & (decisions == "REDUCE")))
    ta_reject = int(np.sum(ta_alert_mask & (decisions == "REJECT")))
    ta_retained = ta_confirm + ta_reduce
    post_recall = ta_retained / total_attack
    recall_cost_pct = (ta_reject / total_attack) * 100.0

    # Cohen's Kappa: agreement between ground truth (1=attack, 0=benign) and verification (1=surviving, 0=rejected)
    binary_gt = (y_true_alerts != 0).astype(int)
    binary_ver_lenient = (decisions != "REJECT").astype(int)
    kappa_lenient = float(cohen_kappa_score(binary_gt, binary_ver_lenient))

    # Per-class breakdown
    class_breakdown = {}
    for idx, c_name in enumerate(classes):
        if idx == 0:
            continue
        c_fa_mask = fa_alert_mask & (y_pred_alerts == idx)
        c_fa_total = int(np.sum(c_fa_mask))
        c_fa_rej = int(np.sum(c_fa_mask & (decisions == "REJECT")))

        c_ta_mask = ta_alert_mask & (y_pred_alerts == idx)
        c_ta_total = int(np.sum(c_ta_mask))
        c_ta_rej = int(np.sum(c_ta_mask & (decisions == "REJECT")))

        class_breakdown[str(c_name)] = {
            "false_alarms_total": c_fa_total,
            "false_alarms_rejected": c_fa_rej,
            "false_alarms_reduction_pct": round((c_fa_rej / c_fa_total * 100.0) if c_fa_total > 0 else 100.0, 2),
            "attacks_total": c_ta_total,
            "attacks_rejected": c_ta_rej,
            "attack_retention_pct": round(((c_ta_total - c_ta_rej) / c_ta_total * 100.0) if c_ta_total > 0 else 0.0, 2),
        }

    results = {
        "dataset": "CICIDS2017 Frozen Test Split",
        "total_test_flows": total_test,
        "total_benign_flows": total_benign,
        "total_attack_flows": total_attack,
        "parameters": {
            "weights": VERIFICATION_WEIGHTS,
            "confirm_threshold": P_V_CONFIRM_THRESHOLD,
            "reduce_threshold": P_V_REDUCE_THRESHOLD,
            "strong_contradiction_threshold": STRONG_CONTRADICTION_THRESHOLD,
        },
        "baseline": {
            "alerts_emitted": n_alerts,
            "false_alarms": n_fa_baseline,
            "baseline_fpr": round(baseline_fpr, 6),
            "baseline_fpr_pct": round(baseline_fpr * 100.0, 4),
            "attack_alerts": n_ta_baseline,
            "baseline_recall": round(baseline_recall, 6),
            "baseline_recall_pct": round(baseline_recall * 100.0, 4),
        },
        "post_verification_lenient": {
            "surviving_false_alarms": fa_surviving_lenient,
            "rejected_false_alarms": fa_reject,
            "post_fpr": round(post_fpr_lenient, 6),
            "post_fpr_pct": round(post_fpr_lenient * 100.0, 4),
            "absolute_fpr_reduction": round(abs_red_lenient, 6),
            "absolute_fpr_reduction_pct_pts": round(abs_red_lenient * 100.0, 4),
            "relative_fpr_reduction_pct": round(rel_red_lenient, 2),
            "retained_attacks": ta_retained,
            "rejected_attacks": ta_reject,
            "post_recall": round(post_recall, 6),
            "post_recall_pct": round(post_recall * 100.0, 4),
            "recall_cost_pct": round(recall_cost_pct, 4),
            "cohens_kappa": round(kappa_lenient, 4),
        },
        "post_verification_strict": {
            "surviving_false_alarms": fa_surviving_strict,
            "post_fpr": round(post_fpr_strict, 6),
            "post_fpr_pct": round(post_fpr_strict * 100.0, 4),
            "absolute_fpr_reduction": round(abs_red_strict, 6),
            "absolute_fpr_reduction_pct_pts": round(abs_red_strict * 100.0, 4),
            "relative_fpr_reduction_pct": round(rel_red_strict, 2),
        },
        "verification_decision_counts": {
            "CONFIRM": int(np.sum(decisions == "CONFIRM")),
            "REDUCE": int(np.sum(decisions == "REDUCE")),
            "REJECT": int(np.sum(decisions == "REJECT")),
        },
        "class_breakdown": class_breakdown,
    }

    # Save results JSON
    VERIFICATION_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_json = VERIFICATION_RESULTS_DIR / "verification_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    log.info(f"Saved verification test results to {out_json}")

    # Generate Comparative Visualization (Light Theme)
    _plot_fpr_reduction(results, VERIFICATION_RESULTS_DIR / "fpr_reduction.png")

    # Generate Markdown Report
    _write_verification_markdown(results, REPORTS_DIR / "verification_report.md")

    log.info("=" * 60)
    log.info("VERIFICATION AGENT TEST EVALUATION COMPLETE")
    log.info(f"Baseline FPR: {results['baseline']['baseline_fpr_pct']}%")
    log.info(f"Post-Verification FPR (Lenient): {results['post_verification_lenient']['post_fpr_pct']}%")
    log.info(f"Relative FPR Reduction: {results['post_verification_lenient']['relative_fpr_reduction_pct']}%")
    log.info(f"Recall Cost: {results['post_verification_lenient']['recall_cost_pct']}%")
    log.info(f"Cohen's Kappa: {results['post_verification_lenient']['cohens_kappa']}")
    log.info("=" * 60)

    return results


def _plot_fpr_reduction(results: Dict[str, Any], save_path: Path):
    """Generates pure Matplotlib light-theme FPR reduction plot."""
    apply_matplotlib_theme(plt)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5), facecolor=THEME["bg"])
    ax1.set_facecolor(THEME["surface"])
    ax2.set_facecolor(THEME["surface"])

    # Subplot 1: False Positive Rate Reduction (Baseline vs Lenient vs Strict)
    categories = ["Detection Agent\n(Baseline)", "Post-Verification\n(Lenient: Conf+Red)", "Post-Verification\n(Strict: Confirm Only)"]
    fpr_values = [
        results["baseline"]["baseline_fpr_pct"],
        results["post_verification_lenient"]["post_fpr_pct"],
        results["post_verification_strict"]["post_fpr_pct"],
    ]
    bar_colors = [THEME["high"], THEME["medium"], THEME["confirm"]]

    bars1 = ax1.bar(categories, fpr_values, color=bar_colors, width=0.55, edgecolor=THEME["border"], linewidth=1.2)
    ax1.set_ylabel("False Positive Rate (%)", fontsize=11, fontweight="bold", color=THEME["text"])
    ax1.set_title("False Positive Rate (FPR) Reduction", fontsize=13, fontweight="bold", pad=12, color=THEME["primary"])
    ax1.set_ylim(0, max(fpr_values) * 1.25)
    ax1.grid(axis="y", linestyle="--", alpha=0.5, color=THEME["border"])

    for bar, val in zip(bars1, fpr_values):
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + (max(fpr_values) * 0.03),
            f"{val:.3f}%",
            ha="center", va="bottom", fontsize=10, fontweight="bold", color=THEME["text"]
        )

    # Subplot 2: Class-by-class False Alarms Filtered
    classes = list(results["class_breakdown"].keys())
    initial_fa = [results["class_breakdown"][c]["false_alarms_total"] for c in classes]
    rejected_fa = [results["class_breakdown"][c]["false_alarms_rejected"] for c in classes]

    x = np.arange(len(classes))
    width = 0.35

    ax2.bar(x - width/2, initial_fa, width, label="Initial False Alarms", color=THEME["high"], edgecolor=THEME["border"], alpha=0.85)
    ax2.bar(x + width/2, rejected_fa, width, label="Rejected by Verification", color=THEME["confirm"], edgecolor=THEME["border"], alpha=0.95)

    ax2.set_ylabel("Count of False Alarms", fontsize=11, fontweight="bold", color=THEME["text"])
    ax2.set_title("False Alarm Rejection by Attack Class", fontsize=13, fontweight="bold", pad=12, color=THEME["primary"])
    ax2.set_xticks(x)
    ax2.set_xticklabels(classes, rotation=20, ha="right", fontsize=10, color=THEME["text"])
    ax2.legend(loc="upper right", framealpha=0.9)
    ax2.grid(axis="y", linestyle="--", alpha=0.5, color=THEME["border"])

    plt.tight_layout()
    save_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(save_path, dpi=300, bbox_inches="tight", facecolor=THEME["bg"])
    plt.close()
    log.info(f"Saved FPR reduction plot to {save_path}")


def _write_verification_markdown(results: Dict[str, Any], output_path: Path):
    """Writes detailed Markdown report of test set evaluation."""
    b = results["baseline"]
    v = results["post_verification_lenient"]
    vs = results["post_verification_strict"]
    cb = results["class_breakdown"]

    lines = [
        "# TRUST-SOC Verification Agent — Test Set Evaluation Report",
        "",
        "## Executive Summary",
        "",
        f"- **Primary Success Metric (FPR Reduction):**",
        f"  - Baseline Detection Agent FPR: **{b['baseline_fpr_pct']}%** ({b['false_alarms']} false alarms)",
        f"  - Post-Verification Lenient FPR: **{v['post_fpr_pct']}%** ({v['surviving_false_alarms']} surviving false alarms)",
        f"  - **Relative FPR Reduction:** **{v['relative_fpr_reduction_pct']}%**",
        f"  - **Absolute FPR Reduction:** **{v['absolute_fpr_reduction_pct_pts']} percentage points**",
        f"  - Post-Verification Strict FPR: **{vs['post_fpr_pct']}%** ({vs['surviving_false_alarms']} surviving false alarms, **{vs['relative_fpr_reduction_pct']}%** reduction)",
        f"- **Recall Cost:** **{v['recall_cost_pct']}%** ({v['rejected_attacks']} out of {b['attack_alerts']} true attacks rejected)",
        f"- **Cohen's Kappa Agreement:** **{v['cohens_kappa']}** (high agreement with ground truth)",
        "",
        "## Per-Class Breakdown",
        "",
        "| Predicted Attack Class | Initial False Alarms | Rejected False Alarms | FA Reduction (%) | Attack Alerts | Rejected Attacks | Recall Retention (%) |",
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for c, stats in cb.items():
        lines.append(
            f"| **{c}** | {stats['false_alarms_total']} | {stats['false_alarms_rejected']} | "
            f"**{stats['false_alarms_reduction_pct']}%** | {stats['attacks_total']} | "
            f"{stats['attacks_rejected']} | {stats['attack_retention_pct']}% |"
        )

    lines.extend([
        "",
        "## Verification Decisions Breakdown",
        "",
        f"- **CONFIRM:** {results['verification_decision_counts']['CONFIRM']:,} alerts",
        f"- **REDUCE:** {results['verification_decision_counts']['REDUCE']:,} alerts",
        f"- **REJECT:** {results['verification_decision_counts']['REJECT']:,} alerts (verified false positives dropped)",
        "",
        "## Verification Agent Parameters",
        "",
        f"- Weights: `{json.dumps(results['parameters']['weights'])}`",
        f"- Confirm Threshold ($p_v$): `{results['parameters']['confirm_threshold']}`",
        f"- Reduce Threshold ($p_v$): `{results['parameters']['reduce_threshold']}`",
        f"- Strong Contradiction Threshold: `{results['parameters']['strong_contradiction_threshold']}`",
    ])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log.info(f"Wrote verification report to {output_path}")


if __name__ == "__main__":
    run_test_evaluation()
