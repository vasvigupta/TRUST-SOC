"""
TRUST-SOC Configuration
=======================
All project-wide settings live here.
Do NOT scatter magic numbers or paths across other files.
"""

import os
from pathlib import Path

# ─────────────────────────────────────────
# Paths
# ─────────────────────────────────────────
ROOT_DIR   = Path(__file__).resolve().parents[2]   # TRUST-SOC/
DATA_DIR   = ROOT_DIR / "data"
RAW_DIR    = DATA_DIR / "raw" / "CICIDS2017"
PROC_DIR   = DATA_DIR / "processed"
SAMPLE_DIR = DATA_DIR / "sample"

MODELS_DIR  = ROOT_DIR / "models"
RESULTS_DIR = ROOT_DIR / "results"

METRICS_DIR   = RESULTS_DIR / "metrics"
CM_DIR        = RESULTS_DIR / "confusion_matrix"
SHAP_DIR      = RESULTS_DIR / "shap"
REPORTS_DIR   = RESULTS_DIR / "reports"

# Processed artefacts
PROCESSED_X_TRAIN = PROC_DIR / "X_train.parquet"
PROCESSED_X_VAL   = PROC_DIR / "X_val.parquet"
PROCESSED_X_TEST  = PROC_DIR / "X_test.parquet"
PROCESSED_Y_TRAIN = PROC_DIR / "y_train.parquet"
PROCESSED_Y_VAL   = PROC_DIR / "y_val.parquet"
PROCESSED_Y_TEST  = PROC_DIR / "y_test.parquet"

SCALER_PATH        = MODELS_DIR / "scaler.joblib"
ENCODER_PATH       = MODELS_DIR / "label_encoder.joblib"
FEATURE_NAMES_PATH = MODELS_DIR / "feature_names.joblib"
MODEL_PATH         = MODELS_DIR / "rf_detection_agent.joblib"

REPLAY_SAMPLE_PATH = SAMPLE_DIR / "replay_sample.csv"

# ─────────────────────────────────────────
# Reproducibility
# ─────────────────────────────────────────
RANDOM_STATE = 42

# ─────────────────────────────────────────
# Data split ratios
# ─────────────────────────────────────────
# 70% train | 15% validation | 15% test
TEST_SIZE       = 0.15   # fraction of TOTAL data held out for test
VALIDATION_SIZE = 0.1765 # fraction of remaining (train+val) → gives ~15% of total

# ─────────────────────────────────────────
# Six project-level classes
# ─────────────────────────────────────────
PROJECT_CLASSES = [
    "Benign",
    "DoS/DDoS",
    "Port Scan",
    "Brute Force",
    "Web Attack",
    "Botnet",
]

# ─────────────────────────────────────────
# Label mapping  (original CICIDS2017 → TRUST-SOC class)
# Built after inspecting actual dataset labels — do not modify blindly.
# ─────────────────────────────────────────
LABEL_MAPPING = {
    # ── Benign ──────────────────────────────────────────────────────────
    "BENIGN": "Benign",

    # ── DoS / DDoS ──────────────────────────────────────────────────────
    "DoS slowloris":          "DoS/DDoS",
    "DoS Slowhttptest":       "DoS/DDoS",
    "DoS Hulk":               "DoS/DDoS",
    "DoS GoldenEye":          "DoS/DDoS",
    "Heartbleed":             "DoS/DDoS",
    "DDoS":                   "DoS/DDoS",

    # ── Port Scan ───────────────────────────────────────────────────────
    "PortScan":               "Port Scan",

    # ── Brute Force ─────────────────────────────────────────────────────
    "FTP-Patator":            "Brute Force",
    "SSH-Patator":            "Brute Force",

    # ── Web Attack ──────────────────────────────────────────────────────
    "Web Attack \x96 Brute Force":   "Web Attack",
    "Web Attack \x96 XSS":           "Web Attack",
    "Web Attack \x96 Sql Injection":  "Web Attack",
    "Web Attack – Brute Force":      "Web Attack",
    "Web Attack – XSS":              "Web Attack",
    "Web Attack – Sql Injection":    "Web Attack",

    # ── Botnet ──────────────────────────────────────────────────────────
    "Bot":                    "Botnet",

    # ── Infiltration (mapped to Botnet as closest behaviour class) ──────
    "Infiltration":           "Botnet",
}

# ─────────────────────────────────────────
# Model
# ─────────────────────────────────────────
MODEL_TYPE = "random_forest"   # "xgboost" for future switch

RF_PARAMS = {
    "n_estimators":    100,
    "max_depth":       None,     # unconstrained — change if RAM limited
    "min_samples_split": 5,
    "class_weight":    "balanced",
    "n_jobs":          -1,
    "random_state":    RANDOM_STATE,
}

# ─────────────────────────────────────────
# SHAP
# ─────────────────────────────────────────
SHAP_SAMPLE_SIZE   = 500    # rows sampled from test set for global SHAP (raise for more precision)
SHAP_TOP_K         = 15     # top-k features shown in bar plot

# ─────────────────────────────────────────
# Replay
# ─────────────────────────────────────────
REPLAY_N_RECORDS   = 50    # default records to replay in demo mode
REPLAY_DELAY_SEC   = 0.0   # 0 = as fast as possible

# ─────────────────────────────────────────
# Database (SQLite)
# ─────────────────────────────────────────
DB_PATH = ROOT_DIR / "trust_soc.db"

# ─────────────────────────────────────────
# API (FastAPI / uvicorn)
# ─────────────────────────────────────────
API_HOST    = "0.0.0.0"
API_PORT    = 8000
CORS_ORIGINS = [
    "http://localhost:3000",   # React dev server
    "http://127.0.0.1:3000",
    "http://localhost:5173",   # Vite default
    "http://127.0.0.1:5173",
]

# ─────────────────────────────────────────
# Preprocessing
# ─────────────────────────────────────────
# Columns that should never be used as features
DROP_COLUMNS = [
    " Label",
    "Label",
    "label",
    "Flow ID",
    " Flow ID",
    "Source IP",
    " Source IP",
    "Source Port",
    " Source Port",
    "Destination IP",
    " Destination IP",
    "Destination Port",
    " Destination Port",
    "Protocol",
    " Protocol",
    "Timestamp",
    " Timestamp",
]
