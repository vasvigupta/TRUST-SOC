"""
Tests — Alert structure and Log Replay
"""

import sys
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.ingestion.log_replay import build_alert, LogReplayEngine
from src.detection.model import DetectionAgent
from src.config.config import PROJECT_CLASSES


# ─────────────────────────────────────────────────────────────────
# Alert tests
# ─────────────────────────────────────────────────────────────────

def test_alert_has_required_keys():
    alert = build_alert(
        flow_id=1,
        prediction="Port Scan",
        probability=0.91,
        top_features=[{"feature": "x", "shap_value": 0.3}],
        class_probabilities={"Port Scan": 0.91, "Benign": 0.09},
    )
    for key in ["alert_id", "timestamp", "prediction", "probability",
                "top_features", "status", "verification_result"]:
        assert key in alert, f"Missing key: {key}"


def test_alert_prediction_value():
    alert = build_alert(0, "Benign", 0.99, [], {})
    assert alert["prediction"] == "Benign"


def test_alert_status_detected():
    alert = build_alert(0, "DoS/DDoS", 0.80, [], {})
    assert alert["status"] == "DETECTED"


def test_alert_verification_not_implemented():
    alert = build_alert(0, "Benign", 0.9, [], {})
    assert alert["verification_result"] == "NOT_IMPLEMENTED"


def test_alert_probability_rounded():
    alert = build_alert(0, "Botnet", 0.123456789, [], {})
    # should be rounded to 4 dp
    assert alert["probability"] == round(0.123456789, 4)


def test_alert_id_format():
    alert = build_alert(42, "Port Scan", 0.7, [], {})
    assert alert["alert_id"] == "ALERT-00042"


# ─────────────────────────────────────────────────────────────────
# Replay engine tests (uses a synthetic CSV + agent)
# ─────────────────────────────────────────────────────────────────

def make_agent_and_sample(tmp_path):
    rng   = np.random.default_rng(0)
    n, f  = 50, 10
    X     = rng.random((n, f))
    labels_raw = np.array(PROJECT_CLASSES * (n // len(PROJECT_CLASSES) + 1))[:n]
    le    = LabelEncoder()
    y     = le.fit_transform(labels_raw)
    clf   = RandomForestClassifier(n_estimators=5, random_state=0)
    clf.fit(X, y)

    feature_names = [f"feat_{i}" for i in range(f)]
    agent = DetectionAgent(clf, le, feature_names)

    # Save sample CSV
    df = pd.DataFrame(X, columns=feature_names)
    df["TrustSOC_Label"] = y
    sample_path = tmp_path / "replay_sample.csv"
    df.to_csv(sample_path, index=False)
    return agent, sample_path


def test_replay_load(tmp_path):
    agent, sample_path = make_agent_and_sample(tmp_path)
    engine = LogReplayEngine(agent, sample_path=sample_path, use_shap=False)
    engine.load()
    assert engine._df is not None
    assert len(engine._df) == 50


def test_replay_next_record(tmp_path):
    agent, sample_path = make_agent_and_sample(tmp_path)
    engine = LogReplayEngine(agent, sample_path=sample_path, use_shap=False)
    engine.load()
    engine.start()
    alert = engine.next_record()
    assert alert is not None
    assert "prediction" in alert
    assert alert["prediction"] in PROJECT_CLASSES


def test_replay_n(tmp_path):
    agent, sample_path = make_agent_and_sample(tmp_path)
    engine = LogReplayEngine(agent, sample_path=sample_path, use_shap=False)
    engine.load()
    engine.start()
    alerts = engine.replay_n(10)
    assert len(alerts) == 10


def test_replay_position_advances(tmp_path):
    agent, sample_path = make_agent_and_sample(tmp_path)
    engine = LogReplayEngine(agent, sample_path=sample_path, use_shap=False)
    engine.load()
    engine.start()
    engine.replay_n(5)
    assert engine._pos == 5


def test_replay_end_of_data(tmp_path):
    agent, sample_path = make_agent_and_sample(tmp_path)
    engine = LogReplayEngine(agent, sample_path=sample_path, use_shap=False)
    engine.load()
    engine.start()
    alerts = engine.replay_n(1000)   # more than available
    assert len(alerts) == 50         # capped at dataset size


def test_replay_missing_file():
    from src.detection.model import DetectionAgent as DA
    rng = np.random.default_rng(0)
    clf = RandomForestClassifier(n_estimators=5, random_state=0)
    clf.fit(rng.random((20, 5)), [0] * 20)
    le = LabelEncoder(); le.fit(["Benign"])
    agent = DA(clf, le, [f"f{i}" for i in range(5)])

    engine = LogReplayEngine(agent, sample_path=Path("/nonexistent/sample.csv"), use_shap=False)
    with pytest.raises(FileNotFoundError):
        engine.load()
