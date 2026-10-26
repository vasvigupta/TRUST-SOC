"""
Signal (b): Statistical Corroboration (s)
=========================================
Uses an independently trained Isolation Forest (fitted STRICTLY on the training split's
benign flows only) to verify whether the flow is statistically anomalous.

Strictly adheres to Section 4.2(b) and Section 11 (Milestone 2) specifications.
Does NOT inspect ground_truth or Detection Agent probability p_d.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

from src.config.config import (
    PROCESSED_X_TRAIN,
    PROCESSED_Y_TRAIN,
    IF_MODEL_PATH,
    STRONG_CONTRADICTION_THRESHOLD,
    RANDOM_STATE,
)

log = logging.getLogger("TRUST-SOC.verification.statistical")


def train_isolation_forest(
    x_train_path: Path = PROCESSED_X_TRAIN,
    y_train_path: Path = PROCESSED_Y_TRAIN,
    save_path: Path = IF_MODEL_PATH,
    subsample_size: int = 30000,
    random_state: int = RANDOM_STATE,
) -> Dict[str, Any]:
    """
    Trains an Isolation Forest strictly on benign training flows.
    Computes calibration parameters from the benign training distribution.
    """
    log.info("Loading training data for Isolation Forest...")
    X_train = joblib.load(x_train_path)
    y_train = joblib.load(y_train_path)

    # Strictly benign flows only (class 0)
    benign_mask = (y_train == 0)
    X_benign = X_train[benign_mask]
    n_benign = len(X_benign)
    log.info(f"Total benign training flows available: {n_benign}")

    if n_benign > subsample_size:
        np.random.seed(random_state)
        sample_idx = np.random.choice(n_benign, size=subsample_size, replace=False)
        X_fit = X_benign[sample_idx]
    else:
        X_fit = X_benign

    log.info(f"Fitting IsolationForest on {len(X_fit)} benign flows...")
    iforest = IsolationForest(
        n_estimators=100,
        max_samples=1024,
        contamination="auto",
        random_state=random_state,
        n_jobs=-1,
    )
    iforest.fit(X_fit)

    # Compute calibration thresholds on training benign set
    df_scores = iforest.decision_function(X_fit)
    q01 = float(np.percentile(df_scores, 1.0))
    q95 = float(np.percentile(df_scores, 95.0))
    q50 = float(np.median(df_scores))

    log.info(f"Isolation Forest calibrated: q01={q01:.4f}, median={q50:.4f}, q95={q95:.4f}")

    artefact = {
        "model": iforest,
        "q01": q01,
        "q95": q95,
        "q50": q50,
        "trained_on": "Benign flows only (CICIDS2017 training split)",
    }

    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artefact, save_path)
    log.info(f"Saved Isolation Forest artefact to {save_path}")
    return artefact


class StatisticalVerifier:
    """Evaluates statistical anomaly score s in [0, 1] using the trained Isolation Forest."""

    def __init__(
        self,
        model_path: Path = IF_MODEL_PATH,
        strong_contra_thresh: float = STRONG_CONTRADICTION_THRESHOLD,
    ):
        self.strong_contra_thresh = strong_contra_thresh
        if not model_path.exists():
            log.warning(f"Isolation Forest model not found at {model_path}. Training now...")
            self.artefact = train_isolation_forest(save_path=model_path)
        else:
            self.artefact = joblib.load(model_path)

        self.model: IsolationForest = self.artefact["model"]
        self.q01 = float(self.artefact["q01"])
        self.q95 = float(self.artefact["q95"])

    def verify_flow(self, flow_vector: Union[np.ndarray, list]) -> Dict[str, Any]:
        """
        Computes statistical anomaly corroboration score s in [0, 1].

        Args:
            flow_vector: 1D array of 68 scaled features matching training pipeline.

        Returns:
            Dict conforming to common signal contract:
            {"score": float, "strongly_contradictory": bool, "details": dict}
        """
        arr = np.asarray(flow_vector, dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)

        raw_score = float(self.model.decision_function(arr)[0])

        # Monotonic mapping to [0, 1] where 1 = strongly anomalous (attack)
        # raw_score >= q95 -> definitely inlier / benign -> score = 0.0
        # raw_score <= q01 -> definitely outlier / attack -> score = 1.0
        denom = self.q95 - self.q01
        if denom <= 0:
            denom = 1.0

        score = (self.q95 - raw_score) / denom
        score = max(0.0, min(1.0, float(score)))

        interpretation = (
            "Statistical anomaly detected (corroborates attack)"
            if score >= 0.50
            else "Traffic statistically conforms to benign baseline (contradicts attack)"
        )

        details = {
            "raw_anomaly_score": round(raw_score, 4),
            "inlier_threshold_q95": round(self.q95, 4),
            "outlier_threshold_q01": round(self.q01, 4),
            "interpretation": interpretation,
        }

        return {
            "score": round(score, 4),
            "strongly_contradictory": score < self.strong_contra_thresh,
            "details": details,
        }
