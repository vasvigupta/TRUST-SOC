"""
SHAP Explainability Module
===========================
Generates global and per-sample SHAP explanations for the
Random Forest Detection Agent.

Key design decisions
---------------------
- For GLOBAL importance: we use a fast approach combining
  SHAP TreeExplainer on a small sample (100 rows) to get
  real SHAP values, plus RF feature_importances_ as fallback.
- For INDIVIDUAL predictions: SHAP TreeExplainer on a single row
  (very fast — milliseconds).
- check_additivity=False is used to skip the slow additivity
  verification step (safe for approximate explanations).
- Plots are saved to results/shap/.
"""

import sys
import json
import logging
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.config.config import (
    SHAP_DIR, SHAP_SAMPLE_SIZE, SHAP_TOP_K,
    PROCESSED_X_TEST, PROCESSED_Y_TEST, RANDOM_STATE,
)
from src.detection.model import DetectionAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("TRUST-SOC.shap")


# ─────────────────────────────────────────────────────────────────
# Global importance via RF feature_importances_ + SHAP validation
# ─────────────────────────────────────────────────────────────────

def compute_global_importance(agent: DetectionAgent, X_test: pd.DataFrame,
                               sample_size: int = SHAP_SAMPLE_SIZE):
    """
    Compute global feature importances using SHAP TreeExplainer
    on a small sample. Falls back to RF feature_importances_ if
    SHAP takes too long.

    Returns (importance_series, method_used).
    """
    import shap

    rng = np.random.default_rng(RANDOM_STATE)
    # Use small sample (100 rows) for global SHAP — fast and representative
    n_global = min(100, len(X_test))
    idx = rng.choice(len(X_test), size=n_global, replace=False)
    X_sample = X_test.iloc[idx].reset_index(drop=True)

    log.info(f"Computing SHAP global importance on {n_global} samples…")

    try:
        explainer = shap.TreeExplainer(
            agent.classifier,
            feature_perturbation="tree_path_dependent",
        )
        # shap_values returns list[n_classes] of (n_samples, n_features)
        # check_additivity=False → skips slow additivity check
        sv = explainer.shap_values(X_sample, check_additivity=False)

        # Handle list (old shap) vs ndarray (new shap >= 0.46)
        if isinstance(sv, list):
            # list[n_classes] of (n_samples, n_features)
            mean_abs = np.mean([np.abs(s) for s in sv], axis=0)
        elif isinstance(sv, np.ndarray):
            if sv.ndim == 3:
                # (n_samples, n_features, n_classes)
                mean_abs = np.abs(sv).mean(axis=2)   # → (n_samples, n_features)
            else:
                mean_abs = np.abs(sv)
        else:
            raise ValueError(f"Unexpected SHAP output type: {type(sv)}")

        importance = pd.Series(
            mean_abs.mean(axis=0), index=X_sample.columns
        )
        log.info("SHAP global importance computed successfully.")
        return importance, "shap"

    except Exception as e:
        log.warning(f"SHAP global failed ({e}), falling back to RF feature_importances_")
        importance = pd.Series(
            agent.classifier.feature_importances_,
            index=list(agent.feature_names),
        )
        return importance, "rf_importance"


def plot_global_importance(importance: pd.Series, method: str,
                            save_dir: Path = SHAP_DIR):
    """Bar plot of top-k global feature importances."""
    save_dir.mkdir(parents=True, exist_ok=True)

    top = importance.nlargest(SHAP_TOP_K)
    label = "Mean |SHAP Value|" if method == "shap" else "RF Feature Importance (Gini)"
    title_suffix = "(SHAP)" if method == "shap" else "(RF Gini — SHAP fallback)"

    fig, ax = plt.subplots(figsize=(10, 7))
    top.sort_values().plot(kind="barh", ax=ax, color="#1565C0", edgecolor="white")
    ax.set_xlabel(label, fontsize=11)
    ax.set_title(
        f"TRUST-SOC — Top {SHAP_TOP_K} Global Feature Importances {title_suffix}",
        fontsize=12,
    )
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()

    path = save_dir / "shap_summary_bar.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    log.info(f"Global importance bar plot → {path}")

    # Save top features JSON
    json_path = save_dir / "top_features.json"
    with open(json_path, "w") as f:
        json.dump(
            [{"feature": k, "importance": round(float(v), 6)}
             for k, v in top.items()],
            f, indent=2,
        )
    log.info(f"Top features JSON → {json_path}")
    return top


# ─────────────────────────────────────────────────────────────────
# Individual prediction explanation (single row — fast)
# ─────────────────────────────────────────────────────────────────

def explain_single_prediction(agent: DetectionAgent,
                               x_row,
                               class_names: list) -> dict:
    """
    SHAP explanation for ONE network-flow record.
    Single-row TreeExplainer is fast (milliseconds).

    Returns dict compatible with the Alert structure:
      { prediction, confidence, top_features, class_probabilities }
    """
    import shap

    # Full detection result
    result   = agent.predict_single(x_row)
    pred_lbl = result["prediction"]
    pred_enc = result["encoded_label"]

    # Reshape to (1, n_features)
    if hasattr(x_row, "values"):
        x_2d = x_row.values.reshape(1, -1)
        feat_names = list(x_row.index)
    else:
        x_2d = np.array(x_row).reshape(1, -1)
        feat_names = agent.feature_names

    explainer = shap.TreeExplainer(
        agent.classifier,
        feature_perturbation="tree_path_dependent",
    )
    sv = explainer.shap_values(x_2d, check_additivity=False)

    # Handle different SHAP output formats across versions:
    #   Old (< 0.46): list[n_classes] of (n_samples, n_features)
    #   New (>= 0.46): ndarray of shape (n_samples, n_features, n_classes)
    #                  or (n_features, n_classes) for single sample
    if isinstance(sv, list):
        # Old format — list per class
        sv_pred = sv[pred_enc][0]           # shape (n_features,)
    elif isinstance(sv, np.ndarray):
        if sv.ndim == 3:
            # (n_samples, n_features, n_classes)
            sv_pred = sv[0, :, pred_enc]    # shape (n_features,)
        elif sv.ndim == 2:
            if sv.shape[0] == x_2d.shape[1]:
                # (n_features, n_classes)
                sv_pred = sv[:, pred_enc]   # shape (n_features,)
            else:
                # (n_classes, n_features)  — less common
                sv_pred = sv[pred_enc, :]   # shape (n_features,)
        else:
            sv_pred = sv                    # already 1D
    else:
        sv_pred = np.zeros(len(feat_names))


    contributions = pd.Series(sv_pred, index=feat_names)
    top_k = contributions.abs().nlargest(SHAP_TOP_K)

    top_features = [
        {"feature": feat, "shap_value": round(float(contributions[feat]), 6)}
        for feat in top_k.index
    ]

    return {
        "prediction":          pred_lbl,
        "confidence":          round(result["confidence"], 4),
        "top_features":        top_features,
        "class_probabilities": result["class_probabilities"],
    }


# ─────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────

def run_shap_analysis():
    """Full SHAP analysis: global importance + individual explanation."""
    log.info("=" * 60)
    log.info("TRUST-SOC  |  SHAP Explainability")
    log.info("=" * 60)

    agent = DetectionAgent.load()
    class_names = list(agent.encoder.classes_)

    X_test = pd.read_parquet(PROCESSED_X_TEST)
    y_test = pd.read_parquet(PROCESSED_Y_TEST)["label"].values

    # 1. Global importance
    importance, method = compute_global_importance(agent, X_test)
    top = plot_global_importance(importance, method)

    log.info(f"\nTop {SHAP_TOP_K} features globally ({method}):")
    for feat, val in top.items():
        log.info(f"  {feat:<45} {val:.6f}")

    # 2. Individual explanation (first test sample)
    log.info("\nIndividual prediction explanation (first test sample):")
    expl = explain_single_prediction(agent, X_test.iloc[0], class_names)

    log.info(f"  Prediction:  {expl['prediction']}")
    log.info(f"  Confidence:  {expl['confidence']:.4f}")
    log.info(f"  Top features:")
    for tf in expl["top_features"][:5]:
        log.info(f"    {tf['feature']:<45} SHAP={tf['shap_value']:+.4f}")

    # Save individual explanation
    out_path = SHAP_DIR / "sample_explanation.json"
    SHAP_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(expl, indent=2))
    log.info(f"\nIndividual explanation saved → {out_path}")

    log.info("=" * 60)
    log.info("SHAP analysis COMPLETE.")
    log.info("=" * 60)
    return top, expl


if __name__ == "__main__":
    run_shap_analysis()
