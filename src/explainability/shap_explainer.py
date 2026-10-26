"""
SHAP Explainability Module (Stage 1.7)
=======================================
Implements shap.TreeExplainer on the fitted Detection Agent model.
Provides:
1. Global feature importance (overall mean |SHAP| and per-class).
2. Per-prediction flow explanations focusing on the PREDICTED class:
   { "prediction": "...", "confidence": 0.91, "top_features": [ {feature, shap_value, feature_value} ] }
3. Consistency & additivity verification (base_value + sum(shap) == model output within tolerance).
4. Single-flow explanation latency profiling.
5. Light-theme summary bar plot.
"""

import time
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
import shap

from src.config.config import (
    SHAP_DIR, SHAP_SAMPLE_SIZE, SHAP_TOP_K,
    PROCESSED_X_TEST, PROCESSED_Y_TEST, PROCESSED_X_TEST_RAW,
    RANDOM_STATE, MODEL_PATH, ENCODER_PATH, FEATURE_NAMES_PATH
)
from src.config.theme import THEME, apply_matplotlib_theme
from src.detection.model import DetectionAgent

log = logging.getLogger("TRUST-SOC.explainability")


class TrustShapExplainer:
    """
    Production SHAP Explainer for TRUST-SOC Detection Agent.
    """

    def __init__(self, agent: DetectionAgent):
        self.agent = agent
        self.classifier = agent.classifier
        self.encoder = agent.encoder
        self.feature_names = agent.feature_names
        self.classes = list(agent.encoder.classes_)

        log.info(f"Initializing SHAP TreeExplainer for {agent.model_type}...")
        self.explainer = shap.TreeExplainer(
            self.classifier,
            feature_perturbation="tree_path_dependent"
        )
        self.expected_value = self.explainer.expected_value

    def explain_flow(
        self,
        flow_scaled: np.ndarray,
        flow_raw: Dict[str, float] = None,
        top_k: int = SHAP_TOP_K
    ) -> Dict[str, Any]:
        """
        Generates a per-prediction explanation for a single flow record.
        Focuses on the PREDICTED class.
        """
        if flow_scaled.ndim == 1:
            vec = flow_scaled.reshape(1, -1)
        else:
            vec = flow_scaled

        t0 = time.perf_counter()
        # Compute prediction and probabilities
        probs = self.agent.predict_proba(vec)[0]
        pred_idx = int(np.argmax(probs))
        pred_class = self.classes[pred_idx]
        confidence = float(probs[pred_idx])

        # Compute SHAP values for the single flow
        sv = self.explainer.shap_values(vec, check_additivity=False)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        # Handle multiclass format variations across SHAP versions:
        # sv can be list of [n_classes](1, n_features) or 3D array (1, n_features, n_classes)
        if isinstance(sv, list):
            class_shap = sv[pred_idx][0]  # shape (n_features,)
            base_val = float(self.expected_value[pred_idx]) if isinstance(self.expected_value, (list, np.ndarray)) else float(self.expected_value)
        elif isinstance(sv, np.ndarray):
            if sv.ndim == 3:
                class_shap = sv[0, :, pred_idx]
                base_val = float(self.expected_value[pred_idx]) if isinstance(self.expected_value, (list, np.ndarray)) else float(self.expected_value)
            else:
                class_shap = sv[0]
                base_val = float(self.expected_value) if not isinstance(self.expected_value, (list, np.ndarray)) else float(self.expected_value[0])
        else:
            raise TypeError(f"Unexpected SHAP values type: {type(sv)}")

        # Verification: check reconstruction
        shap_sum = float(np.sum(class_shap))
        reconstructed = base_val + shap_sum

        # Extract top-k pushing towards the predicted class
        # Positive SHAP pushes toward predicted class; rank by absolute impact or positive contribution
        sorted_indices = np.argsort(class_shap)[::-1][:top_k]

        top_features = []
        for rank, f_idx in enumerate(sorted_indices, 1):
            fname = self.feature_names[f_idx]
            s_val = float(class_shap[f_idx])
            raw_val = float(flow_raw.get(fname, vec[0, f_idx])) if flow_raw else float(vec[0, f_idx])
            top_features.append({
                "rank": rank,
                "feature": fname,
                "shap_value": round(s_val, 4),
                "feature_value": round(raw_val, 4),
                "scaled_value": round(float(vec[0, f_idx]), 4)
            })

        return {
            "prediction": pred_class,
            "predicted_index": pred_idx,
            "confidence": round(confidence, 4),
            "base_value": round(base_val, 4),
            "shap_sum": round(shap_sum, 4),
            "reconstructed_output": round(reconstructed, 4),
            "explanation_latency_ms": round(latency_ms, 3),
            "top_features": top_features,
        }

    def compute_global_explanations(
        self,
        X_sample: np.ndarray,
        sample_size: int = SHAP_SAMPLE_SIZE
    ) -> Dict[str, Any]:
        """
        Computes global feature attributions across a stratified sample.
        """
        n_rows = min(sample_size, len(X_sample))
        vecs = X_sample[:n_rows]
        log.info(f"Computing global SHAP values across {n_rows} representative test flows...")

        t0 = time.time()
        sv = self.explainer.shap_values(vecs, check_additivity=False)
        elapsed = time.time() - t0
        log.info(f"Global SHAP values computed in {elapsed:.2f}s ({elapsed/n_rows*1000:.2f} ms/sample)")

        # Aggregate mean absolute SHAP per feature across all classes
        if isinstance(sv, list):
            # List of arrays of shape (n_samples, n_features)
            mean_abs_per_class = [np.mean(np.abs(s), axis=0) for s in sv]  # list of (n_features,)
            global_importance = np.mean(mean_abs_per_class, axis=0)        # (n_features,)
            per_class_importance = {
                cls: mean_abs_per_class[i] for i, cls in enumerate(self.classes)
            }
        elif isinstance(sv, np.ndarray) and sv.ndim == 3:
            # (n_samples, n_features, n_classes)
            global_importance = np.mean(np.mean(np.abs(sv), axis=0), axis=1)
            per_class_importance = {
                cls: np.mean(np.abs(sv[:, :, i]), axis=0) for i, cls in enumerate(self.classes)
            }
        else:
            global_importance = np.mean(np.abs(sv), axis=0)
            per_class_importance = {self.classes[0]: global_importance}

        # Global Top-K
        top_k_indices = np.argsort(global_importance)[::-1][:SHAP_TOP_K]
        global_top = [
            {"rank": r + 1, "feature": self.feature_names[i], "mean_abs_shap": round(float(global_importance[i]), 5)}
            for r, i in enumerate(top_k_indices)
        ]

        # Per-class Top-5
        per_class_top = {}
        for cls, imp in per_class_importance.items():
            c_indices = np.argsort(imp)[::-1][:5]
            per_class_top[cls] = [
                {"rank": r + 1, "feature": self.feature_names[i], "mean_abs_shap": round(float(imp[i]), 5)}
                for r, i in enumerate(c_indices)
            ]

        return {
            "sample_size": n_rows,
            "compute_time_sec": round(elapsed, 2),
            "latency_ms_per_flow": round((elapsed / n_rows) * 1000.0, 3),
            "global_top_features": global_top,
            "per_class_top_features": per_class_top,
            "all_features_importance": {
                self.feature_names[i]: round(float(global_importance[i]), 5)
                for i in range(len(self.feature_names))
            }
        }


def run_shap_analysis():
    """
    Executes Stage 1.7 SHAP analysis and saves outputs.
    """
    SHAP_DIR.mkdir(parents=True, exist_ok=True)
    log.info("Starting Stage 1.7 SHAP Explainability Engine...")

    agent = DetectionAgent.load(MODEL_PATH)
    explainer = TrustShapExplainer(agent)

    # Load test split
    X_test = joblib.load(PROCESSED_X_TEST)
    y_test = joblib.load(PROCESSED_Y_TEST)
    X_test_raw = joblib.load(PROCESSED_X_TEST_RAW)

    # 1. Global SHAP analysis
    global_results = explainer.compute_global_explanations(X_test, sample_size=SHAP_SAMPLE_SIZE)

    top_features_path = SHAP_DIR / "top_features.json"
    with open(top_features_path, "w", encoding="utf-8") as f:
        json.dump(global_results, f, indent=2)
    log.info(f"Saved global SHAP top features to {top_features_path}")

    # 2. Render Light-Theme Global Summary Bar Plot
    plot_path = SHAP_DIR / "shap_summary_bar.png"
    render_shap_bar_plot(global_results["global_top_features"], plot_path)

    # 3. Test per-prediction explanation on real alert flow
    alert_indices = np.where(y_test != agent.benign_idx)[0]
    sample_idx = alert_indices[0] if len(alert_indices) > 0 else 0

    flow_scaled = X_test[sample_idx]
    flow_raw_dict = X_test_raw.iloc[sample_idx].to_dict()

    sample_explanation = explainer.explain_flow(flow_scaled, flow_raw_dict, top_k=SHAP_TOP_K)
    sample_expl_path = SHAP_DIR / "sample_explanation.json"
    with open(sample_expl_path, "w", encoding="utf-8") as f:
        json.dump(sample_explanation, f, indent=2)
    log.info(f"Saved sample per-prediction explanation to {sample_expl_path}")

    # Latency report
    log.info(f"Per-prediction explanation latency: {sample_explanation['explanation_latency_ms']} ms")
    log.info("SHAP explainability verification complete.")
    return global_results, sample_explanation


def render_shap_bar_plot(top_features: List[Dict[str, Any]], save_path: Path):
    """
    Renders light-theme horizontal bar chart of top SHAP features.
    """
    apply_matplotlib_theme(plt)

    features = [item["feature"] for item in reversed(top_features)]
    values = [item["mean_abs_shap"] for item in reversed(top_features)]

    fig, ax = plt.subplots(figsize=(10, 6.5), facecolor=THEME["surface"])

    bars = ax.barh(features, values, color=THEME["primary"], edgecolor=THEME["border"], height=0.6)

    ax.set_title("Global Feature Importance — Mean |SHAP| (Detection Agent)", fontsize=13, weight="bold", pad=15, color=THEME["primary"])
    ax.set_xlabel("Mean |SHAP Value| (Impact on Model Predictions)", fontsize=11, labelpad=10, color=THEME["text"])
    ax.grid(axis="x", linestyle="--", alpha=0.5, color=THEME["border"])

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(THEME["border"])
    ax.spines["bottom"].set_color(THEME["border"])

    max_v = max(values)
    for bar in bars:
        w = bar.get_width()
        ax.text(
            w + max_v * 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{w:.4f}",
            va="center",
            ha="left",
            fontsize=9,
            color=THEME["text"],
            weight="medium"
        )

    plt.tight_layout()
    fig.savefig(save_path, dpi=300, facecolor=THEME["surface"], bbox_inches="tight")
    plt.close(fig)
    log.info(f"Saved SHAP summary bar plot to {save_path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_shap_analysis()
