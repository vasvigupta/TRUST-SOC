"""
Detection Agent — Model Definition
====================================
Random Forest baseline with a clean interface
that can be swapped for XGBoost later.
"""

import sys
import logging
from pathlib import Path
import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.config.config import RF_PARAMS, MODEL_TYPE, MODEL_PATH, ENCODER_PATH, FEATURE_NAMES_PATH

log = logging.getLogger("TRUST-SOC.model")


class DetectionAgent:
    """
    Wrapper around the trained classifier.

    Usage
    -----
    agent = DetectionAgent.load()
    pred   = agent.predict(X)
    proba  = agent.predict_proba(X)
    """

    def __init__(self, classifier, encoder, feature_names):
        self.classifier    = classifier
        self.encoder       = encoder
        self.feature_names = feature_names

    # ── Training ──────────────────────────────────────────────────

    @classmethod
    def build(cls, model_type: str = MODEL_TYPE):
        """Build an untrained DetectionAgent with the configured classifier."""
        if model_type == "random_forest":
            from sklearn.ensemble import RandomForestClassifier
            clf = RandomForestClassifier(**RF_PARAMS)
        elif model_type == "xgboost":
            from xgboost import XGBClassifier
            clf = XGBClassifier(
                n_estimators=RF_PARAMS["n_estimators"],
                max_depth=6,
                random_state=RF_PARAMS["random_state"],
                n_jobs=-1,
                eval_metric="mlogloss",
                use_label_encoder=False,
            )
        else:
            raise ValueError(f"Unknown model_type: {model_type}. Use 'random_forest' or 'xgboost'.")
        log.info(f"Built {model_type} classifier: {clf}")
        return clf

    # ── Save / Load ───────────────────────────────────────────────

    def save(self, path: Path = MODEL_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"classifier": self.classifier,
             "encoder":    self.encoder,
             "features":   self.feature_names},
            path,
        )
        log.info(f"Model saved → {path}")

    @classmethod
    def load(cls, path: Path = MODEL_PATH):
        if not path.exists():
            raise FileNotFoundError(
                f"ERROR: Detection model not found at {path}.\n"
                "Train the model first:  python -m src.detection.train"
            )
        bundle = joblib.load(path)
        log.info(f"Model loaded ← {path}")
        return cls(bundle["classifier"], bundle["encoder"], bundle["features"])

    # ── Inference ─────────────────────────────────────────────────

    def predict(self, X) -> np.ndarray:
        """Return integer-encoded class predictions."""
        return self.classifier.predict(X)

    def predict_proba(self, X) -> np.ndarray:
        """Return probability array (n_samples, n_classes)."""
        return self.classifier.predict_proba(X)

    def predict_label(self, X) -> list:
        """Return human-readable class labels."""
        preds = self.predict(X)
        return list(self.encoder.inverse_transform(preds))

    def predict_single(self, x_row) -> dict:
        """
        Full prediction for one row.

        Parameters
        ----------
        x_row : array-like, shape (n_features,)

        Returns
        -------
        dict with keys: prediction, probability, class_probabilities
        """
        import pandas as pd
        if hasattr(x_row, "values"):
            x_arr = pd.DataFrame(x_row.values.reshape(1, -1), columns=self.feature_names)
        else:
            x_arr = pd.DataFrame(
                np.array(x_row).reshape(1, -1), columns=self.feature_names
            )

        pred_enc  = self.predict(x_arr)[0]
        proba     = self.predict_proba(x_arr)[0]
        pred_lbl  = self.encoder.inverse_transform([pred_enc])[0]
        confidence = float(proba[pred_enc])

        class_probabilities = {
            cls: float(p)
            for cls, p in zip(self.encoder.classes_, proba)
        }

        return {
            "prediction":         pred_lbl,
            "confidence":         confidence,
            "encoded_label":      int(pred_enc),
            "class_probabilities": class_probabilities,
        }
