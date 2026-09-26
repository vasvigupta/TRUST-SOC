"""
Tests — Detection Agent (unit tests with a tiny synthetic dataset)
"""

import sys
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.detection.model import DetectionAgent
from src.config.config import PROJECT_CLASSES


def make_agent():
    """Build and fit a minimal DetectionAgent for testing."""
    rng = np.random.default_rng(42)
    n, f = 300, 10
    X = rng.random((n, f))
    labels_raw = np.array(PROJECT_CLASSES * (n // len(PROJECT_CLASSES) + 1))[:n]

    le = LabelEncoder()
    y  = le.fit_transform(labels_raw)

    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    clf.fit(X, y)

    feature_names = [f"feat_{i}" for i in range(f)]
    agent = DetectionAgent(clf, le, feature_names)
    return agent, X, y, le


# ── predict ───────────────────────────────────────────────────────

def test_predict_shape():
    agent, X, y, _ = make_agent()
    preds = agent.predict(X[:10])
    assert preds.shape == (10,)


def test_predict_values_valid():
    agent, X, y, le = make_agent()
    preds = agent.predict(X)
    assert set(preds).issubset(set(range(len(le.classes_))))


# ── predict_proba ─────────────────────────────────────────────────

def test_predict_proba_shape():
    agent, X, y, le = make_agent()
    proba = agent.predict_proba(X[:5])
    assert proba.shape == (5, len(le.classes_))


def test_predict_proba_sums_to_one():
    agent, X, y, _ = make_agent()
    proba = agent.predict_proba(X[:20])
    np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-5)


def test_predict_proba_values_in_range():
    agent, X, y, _ = make_agent()
    proba = agent.predict_proba(X)
    assert (proba >= 0).all() and (proba <= 1).all()


# ── predict_label ─────────────────────────────────────────────────

def test_predict_label_returns_strings():
    agent, X, y, _ = make_agent()
    labels = agent.predict_label(X[:5])
    assert isinstance(labels, list)
    for l in labels:
        assert isinstance(l, str)
        assert l in PROJECT_CLASSES


# ── predict_single ────────────────────────────────────────────────

def test_predict_single_keys():
    agent, X, y, _ = make_agent()
    result = agent.predict_single(X[0])
    assert "prediction" in result
    assert "confidence" in result
    assert "class_probabilities" in result


def test_predict_single_confidence_in_range():
    agent, X, y, _ = make_agent()
    result = agent.predict_single(X[0])
    assert 0.0 <= result["confidence"] <= 1.0


def test_predict_single_prediction_is_valid_class():
    agent, X, y, _ = make_agent()
    result = agent.predict_single(X[0])
    assert result["prediction"] in PROJECT_CLASSES


# ── save / load ───────────────────────────────────────────────────

def test_save_and_load(tmp_path):
    agent, X, y, _ = make_agent()
    save_path = tmp_path / "test_model.joblib"
    agent.save(save_path)
    assert save_path.exists()

    loaded = DetectionAgent.load(save_path)
    preds_orig   = agent.predict(X[:10])
    preds_loaded = loaded.predict(X[:10])
    np.testing.assert_array_equal(preds_orig, preds_loaded)


def test_load_missing_raises():
    with pytest.raises(FileNotFoundError):
        DetectionAgent.load(Path("/nonexistent/model.joblib"))
