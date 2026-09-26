"""
Tests — Preprocessing
"""

import sys
import pytest
import numpy as np
import pandas as pd
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.config.config import LABEL_MAPPING, PROJECT_CLASSES
from src.preprocessing.preprocess import (
    apply_label_mapping, clean, find_label_column
)


def make_dummy_df(labels=None):
    """Create a minimal dummy DataFrame mimicking CICIDS2017 structure."""
    if labels is None:
        labels = ["BENIGN", "DoS Hulk", "PortScan", "FTP-Patator",
                  "Web Attack \u2013 Brute Force", "Bot"]
    n = len(labels) * 10
    rng = np.random.default_rng(42)
    df = pd.DataFrame(rng.random((n, 5)), columns=[f"feat_{i}" for i in range(5)])
    # repeat labels to fill n rows
    df["Label"] = (labels * (n // len(labels) + 1))[:n]
    return df


# ── Label mapping ─────────────────────────────────────────────────

def test_label_mapping_benign():
    df = make_dummy_df(["BENIGN"])
    out = apply_label_mapping(df, LABEL_MAPPING)
    assert set(out["TrustSOC_Label"].unique()) == {"Benign"}


def test_label_mapping_dos():
    df = make_dummy_df(["DoS Hulk", "DDoS"])
    out = apply_label_mapping(df, LABEL_MAPPING)
    assert set(out["TrustSOC_Label"].unique()) == {"DoS/DDoS"}


def test_label_mapping_portscan():
    df = make_dummy_df(["PortScan"])
    out = apply_label_mapping(df, LABEL_MAPPING)
    assert set(out["TrustSOC_Label"].unique()) == {"Port Scan"}


def test_label_mapping_brute():
    df = make_dummy_df(["FTP-Patator", "SSH-Patator"])
    out = apply_label_mapping(df, LABEL_MAPPING)
    assert set(out["TrustSOC_Label"].unique()) == {"Brute Force"}


def test_label_mapping_bot():
    df = make_dummy_df(["Bot"])
    out = apply_label_mapping(df, LABEL_MAPPING)
    assert set(out["TrustSOC_Label"].unique()) == {"Botnet"}


def test_unmapped_labels_dropped():
    df = make_dummy_df(["BENIGN", "UnknownAttack"])
    out = apply_label_mapping(df, LABEL_MAPPING)
    assert "UnknownAttack" not in out["TrustSOC_Label"].values
    assert len(out) < len(df)


# ── Six project classes ───────────────────────────────────────────

def test_project_classes_count():
    assert len(PROJECT_CLASSES) == 6


def test_all_mapping_values_in_project_classes():
    for v in LABEL_MAPPING.values():
        assert v in PROJECT_CLASSES, f"{v} not in PROJECT_CLASSES"


# ── Cleaning ──────────────────────────────────────────────────────

def test_clean_removes_duplicates():
    df = make_dummy_df(["BENIGN"])
    df = apply_label_mapping(df, LABEL_MAPPING)
    # artificially duplicate some rows
    df = pd.concat([df, df.head(5)], ignore_index=True)
    cleaned = clean(df)
    assert cleaned.duplicated(subset=[c for c in cleaned.columns if c != "TrustSOC_Label"]).sum() == 0


def test_clean_handles_inf():
    df = make_dummy_df(["BENIGN"])
    df = apply_label_mapping(df, LABEL_MAPPING)
    df.loc[0, "feat_0"] = float("inf")
    cleaned = clean(df)
    assert not cleaned.select_dtypes(include=[float]).isin([float("inf"), float("-inf")]).any().any()


def test_find_label_column():
    df = pd.DataFrame({"Label": ["A", "B"], "x": [1, 2]})
    assert find_label_column(df) == "Label"


def test_find_label_column_missing():
    df = pd.DataFrame({"x": [1, 2]})
    with pytest.raises(KeyError):
        find_label_column(df)
