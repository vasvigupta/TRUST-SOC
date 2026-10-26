"""
Detection Agent — Model Interface & Implementation (Stage 1.4)
===============================================================
Encapsulates the trained classifier (Random Forest baseline or XGBoost alternative).

Interface contract:
    detector = DetectionAgent.load()
    detector.predict(features)
    detector.predict_proba(features)
    detector.detect(flow) -> {predicted_class, probability, class_probabilities, is_alert}
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Union
import numpy as np
import joblib

from src.config.config import (
    MODEL_TYPE, RF_PARAMS, XGB_PARAMS,
    MODEL_PATH, XGB_MODEL_PATH, ENCODER_PATH, FEATURE_NAMES_PATH,
    PROJECT_CLASSES
)

log = logging.getLogger("TRUST-SOC.detection.model")


class DetectionAgent:
    """
    Standardized, swappable Detection Agent wrapper.
    """

    def __init__(self, classifier, encoder, feature_names: List[str], model_type: str = "random_forest"):
        self.classifier = classifier
        self.encoder = encoder
        self.feature_names = feature_names
        self.model_type = model_type
        # Cache benign index
        if hasattr(encoder, "transform"):
            self.benign_idx = int(encoder.transform(["Benign"])[0])
        else:
            self.benign_idx = 0

    @classmethod
    def build(cls, model_type: str = MODEL_TYPE):
        """
        Builds an untrained classifier based on configuration.
        """
        if model_type == "random_forest":
            from sklearn.ensemble import RandomForestClassifier
            clf = RandomForestClassifier(**RF_PARAMS)
        elif model_type == "xgboost":
            from xgboost import XGBClassifier
            clf = XGBClassifier(**XGB_PARAMS)
        else:
            raise ValueError(f"ERROR: Unknown MODEL_TYPE '{model_type}'. Choose 'random_forest' or 'xgboost'.")
        return clf

    def save(self, path: Path = MODEL_PATH):
        """
        Persists the trained model bundle to disk.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "classifier": self.classifier,
            "encoder": self.encoder,
            "feature_names": self.feature_names,
            "model_type": self.model_type,
        }
        joblib.dump(bundle, path, compress=3)
        log.info(f"Saved DetectionAgent ({self.model_type}) to {path}")

    @classmethod
    def load(cls, path: Path = MODEL_PATH):
        """
        Loads a saved DetectionAgent bundle from disk. Fails clearly if absent.
        """
        if not path.exists():
            raise FileNotFoundError(
                f"ERROR: Detection model not found at {path}.\n"
                "Run: python run.py train"
            )
        bundle = joblib.load(path)
        log.info(f"Loaded DetectionAgent ({bundle.get('model_type', 'unknown')}) from {path}")
        return cls(
            classifier=bundle["classifier"],
            encoder=bundle["encoder"],
            feature_names=bundle["feature_names"],
            model_type=bundle.get("model_type", "random_forest")
        )

    def predict(self, features: np.ndarray) -> np.ndarray:
        """
        Predicts integer class indices for an array of feature vectors.
        """
        return self.classifier.predict(features)

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        """
        Returns class probability distribution matrix of shape (n_samples, n_classes).
        """
        return self.classifier.predict_proba(features)

    def detect(self, flow_features: Union[np.ndarray, Dict[str, float]]) -> Dict[str, Any]:
        """
        Inference interface for a single flow record.
        Returns: {predicted_class, probability, class_probabilities, is_alert}
        """
        if isinstance(flow_features, dict):
            # Align dictionary to expected feature list order
            vec = np.array([flow_features.get(f, 0.0) for f in self.feature_names], dtype=np.float32).reshape(1, -1)
        elif isinstance(flow_features, np.ndarray):
            vec = flow_features.reshape(1, -1)
        else:
            vec = np.array(flow_features, dtype=np.float32).reshape(1, -1)

        probs = self.predict_proba(vec)[0]
        pred_idx = int(np.argmax(probs))
        pred_class = str(self.encoder.inverse_transform([pred_idx])[0])
        prob = float(probs[pred_idx])

        class_probabilities = {
            str(cls_name): round(float(p), 4)
            for cls_name, p in zip(self.encoder.classes_, probs)
        }

        is_alert = (pred_class != "Benign")

        return {
            "model": self.model_type,
            "predicted_class": pred_class,
            "probability": round(prob, 4),
            "class_probabilities": class_probabilities,
            "is_alert": is_alert,
        }
