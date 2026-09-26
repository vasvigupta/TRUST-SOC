"""
Detection Agent — Training
===========================
Trains the Random Forest baseline on preprocessed data.
All hyperparameters are read from config.py.
"""

import sys
import logging
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.config.config import MODEL_TYPE, RANDOM_STATE
from src.preprocessing.preprocess import load_splits
from src.detection.model import DetectionAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("TRUST-SOC.train")


def train():
    log.info("=" * 60)
    log.info("TRUST-SOC  |  Detection Agent — Training")
    log.info("=" * 60)

    # 1. Load preprocessed splits
    log.info("Loading preprocessed data…")
    X_train, X_val, X_test, y_train, y_val, y_test = load_splits()
    log.info(f"  X_train: {X_train.shape}   y_train unique: {np.unique(y_train)}")
    log.info(f"  X_val:   {X_val.shape}")
    log.info(f"  X_test:  {X_test.shape}")

    import joblib
    from src.config.config import ENCODER_PATH, FEATURE_NAMES_PATH
    encoder      = joblib.load(ENCODER_PATH)
    feature_names = joblib.load(FEATURE_NAMES_PATH)

    # 2. Build classifier
    clf = DetectionAgent.build(model_type=MODEL_TYPE)

    # 3. Train
    log.info(f"Training {MODEL_TYPE} on {len(y_train):,} samples…")
    clf.fit(X_train, y_train)
    log.info("Training complete.")

    # 4. Quick validation check
    from sklearn.metrics import accuracy_score, f1_score
    y_val_pred = clf.predict(X_val)
    val_acc = accuracy_score(y_val, y_val_pred)
    val_f1  = f1_score(y_val, y_val_pred, average="weighted", zero_division=0)
    log.info(f"  Validation Accuracy: {val_acc:.4f}")
    log.info(f"  Validation F1 (weighted): {val_f1:.4f}")

    # 5. Wrap and save
    agent = DetectionAgent(clf, encoder, feature_names)
    agent.save()

    log.info("=" * 60)
    log.info("Training COMPLETE. Model saved.")
    log.info("=" * 60)
    return agent


if __name__ == "__main__":
    train()
