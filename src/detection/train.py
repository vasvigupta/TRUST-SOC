"""
Detection Agent — Model Training (Stage 1.4 & 1.6)
==================================================
Trains the Random Forest baseline (or XGBoost alternative) on the training split.
Evaluates on the validation split, validates reloadability, and persists weights.
"""

import logging
from pathlib import Path
import numpy as np
import joblib
from sklearn.metrics import classification_report, f1_score, accuracy_score

from src.config.config import (
    MODEL_TYPE, MODEL_PATH, XGB_MODEL_PATH,
    PROCESSED_X_TRAIN, PROCESSED_Y_TRAIN,
    PROCESSED_X_VAL, PROCESSED_Y_VAL,
    ENCODER_PATH, FEATURE_NAMES_PATH
)
from src.detection.model import DetectionAgent

log = logging.getLogger("TRUST-SOC.detection.train")


def train(model_type: str = MODEL_TYPE, save_path: Path = None):
    """
    Trains and persists the Detection Agent.
    """
    if save_path is None:
        save_path = MODEL_PATH if model_type == "random_forest" else XGB_MODEL_PATH

    log.info(f"Loading preprocessed training data for {model_type}...")
    if not PROCESSED_X_TRAIN.exists():
        raise FileNotFoundError(
            f"ERROR: Processed data not found at {PROCESSED_X_TRAIN}.\n"
            "Run: python run.py preprocess"
        )

    X_train = joblib.load(PROCESSED_X_TRAIN)
    y_train = joblib.load(PROCESSED_Y_TRAIN)
    X_val   = joblib.load(PROCESSED_X_VAL)
    y_val   = joblib.load(PROCESSED_Y_VAL)

    encoder       = joblib.load(ENCODER_PATH)
    feature_names = joblib.load(FEATURE_NAMES_PATH)

    log.info(f"Training split: X={X_train.shape}, y={y_train.shape}")
    log.info(f"Validation split: X={X_val.shape}, y={y_val.shape}")

    # Build classifier
    log.info(f"Initializing {model_type} classifier...")
    clf = DetectionAgent.build(model_type=model_type)

    # Train on training split ONLY
    log.info(f"Fitting {model_type} on {len(X_train):,} training flows...")
    clf.fit(X_train, y_train)
    log.info("Training complete.")

    # Validation evaluation (NO test set touched here)
    val_preds = clf.predict(X_val)
    val_acc = accuracy_score(y_val, val_preds)
    val_macro_f1 = f1_score(y_val, val_preds, average="macro", zero_division=0)
    val_weighted_f1 = f1_score(y_val, val_preds, average="weighted", zero_division=0)

    log.info(f"Validation Accuracy:    {val_acc:.4f}")
    log.info(f"Validation Macro F1:    {val_macro_f1:.4f}")
    log.info(f"Validation Weighted F1: {val_weighted_f1:.4f}")

    # Wrap in DetectionAgent and save
    agent = DetectionAgent(
        classifier=clf,
        encoder=encoder,
        feature_names=feature_names,
        model_type=model_type
    )
    agent.save(save_path)

    # Verify model reloadability and prediction parity
    reloaded_agent = DetectionAgent.load(save_path)
    reload_preds = reloaded_agent.predict(X_val[:100])
    orig_preds = agent.predict(X_val[:100])
    np.testing.assert_array_equal(
        reload_preds, orig_preds,
        err_msg="CRITICAL: Reloaded model produced different predictions than original model!"
    )
    log.info("Model reload verification PASSED: Reloaded model gives identical predictions.")

    return agent, {
        "model_type": model_type,
        "val_accuracy": round(float(val_acc), 4),
        "val_macro_f1": round(float(val_macro_f1), 4),
        "val_weighted_f1": round(float(val_weighted_f1), 4),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    train()
