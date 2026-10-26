"""
TRUST-SOC Configuration
=======================
All project-wide settings live here.
Do NOT scatter magic numbers or paths across other files.
"""

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
VERIFICATION_RESULTS_DIR = RESULTS_DIR / "verification"

# Processed artefacts
PROCESSED_X_TRAIN = PROC_DIR / "X_train.joblib"
PROCESSED_X_VAL   = PROC_DIR / "X_val.joblib"
PROCESSED_X_TEST  = PROC_DIR / "X_test.joblib"
PROCESSED_Y_TRAIN = PROC_DIR / "y_train.joblib"
PROCESSED_Y_VAL   = PROC_DIR / "y_val.joblib"
PROCESSED_Y_TEST  = PROC_DIR / "y_test.joblib"

PROCESSED_X_TRAIN_RAW = PROC_DIR / "X_train_unscaled.joblib"
PROCESSED_X_VAL_RAW   = PROC_DIR / "X_val_unscaled.joblib"
PROCESSED_X_TEST_RAW  = PROC_DIR / "X_test_unscaled.joblib"

PROCESSED_TRAIN_FLOWS = PROC_DIR / "train_flow_metadata.joblib"
PROCESSED_VAL_FLOWS   = PROC_DIR / "val_flow_metadata.joblib"
PROCESSED_TEST_FLOWS  = PROC_DIR / "test_flow_metadata.joblib"

SCALER_PATH        = MODELS_DIR / "scaler.joblib"
IMPUTER_PATH       = MODELS_DIR / "imputer.joblib"
ENCODER_PATH       = MODELS_DIR / "label_encoder.joblib"
FEATURE_NAMES_PATH = MODELS_DIR / "feature_names.joblib"
MODEL_PATH         = MODELS_DIR / "rf_detection_agent.joblib"
XGB_MODEL_PATH     = MODELS_DIR / "xgb_detection_agent.joblib"
IF_MODEL_PATH      = MODELS_DIR / "isolation_forest.joblib"
BEHAVIOURAL_PROFILES_PATH = MODELS_DIR / "behavioural_profiles.joblib"

RULES_PATH         = ROOT_DIR / "src" / "config" / "rules.json"
ASSET_CONTEXT_PATH = ROOT_DIR / "src" / "config" / "asset_context.json"

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
VALIDATION_SIZE = 0.17647 # fraction of remaining 85% → gives 15% of total (0.85 * 0.17647 = 0.15)

# ─────────────────────────────────────────
# Six project-level classes (Section 4.1)
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
# Stratified Sampling Targets (Section 7.8)
# Designed to preserve 100% of minority attack classes while remaining
# memory-safe within the host's 1.27 GB available RAM.
# ─────────────────────────────────────────
SAMPLING_TARGETS = {
    "Benign":      120_000,
    "DoS/DDoS":     40_000,
    "Port Scan":    25_000,
    "Brute Force":  13_835,  # 100% preserved
    "Web Attack":    2_180,  # 100% preserved
    "Botnet":        1_966,  # 100% preserved
}

# ─────────────────────────────────────────
# Model Hyperparameters
# ─────────────────────────────────────────
MODEL_TYPE = "random_forest"

RF_PARAMS = {
    "n_estimators":      100,
    "max_depth":         18,     # bounded for memory efficiency & inference speed
    "min_samples_split": 5,
    "min_samples_leaf":  2,
    "class_weight":      "balanced",
    "n_jobs":            -1,
    "random_state":      RANDOM_STATE,
}

XGB_PARAMS = {
    "n_estimators":      100,
    "max_depth":         6,
    "learning_rate":     0.1,
    "subsample":         0.8,
    "colsample_bytree":  0.8,
    "random_state":      RANDOM_STATE,
    "n_jobs":            -1,
    "eval_metric":       "mlogloss",
}

# ─────────────────────────────────────────
# SHAP Configuration
# ─────────────────────────────────────────
SHAP_SAMPLE_SIZE   = 500    # representative sample from test set
SHAP_TOP_K         = 10     # top-k features per prediction

# ─────────────────────────────────────────
# Verification Agent Defaults (Milestone 2)
# ─────────────────────────────────────────
VERIFICATION_WEIGHTS = {
    "r": 0.30,  # rule / context (tuned on validation split)
    "s": 0.25,  # statistical (Isolation Forest)
    "b": 0.25,  # behavioural baseline
    "e": 0.20,  # explanation consistency
}
P_V_CONFIRM_THRESHOLD = 0.70
P_V_REDUCE_THRESHOLD  = 0.40
STRONG_CONTRADICTION_THRESHOLD = 0.20
BEHAVIOURAL_WINDOW_SIZE = 50

# ─────────────────────────────────────────
# Confidence Scoring Engine (Section 4.3)
# ─────────────────────────────────────────
CONFIDENCE_WEIGHTS = {
    "alpha": 0.40,  # Detection probability p_d
    "beta":  0.40,  # Verification agreement p_v
    "gamma": 0.20,  # Normalized rule corroboration r_corr
}
BAND_HIGH_THRESHOLD   = 0.80
BAND_MEDIUM_THRESHOLD = 0.50

# ─────────────────────────────────────────
# Replay Simulation
# ─────────────────────────────────────────
REPLAY_DEFAULT_RATE = 10.0   # records per second
REPLAY_BATCH_SIZE   = 50

# ─────────────────────────────────────────
# Database (SQLite)
# ─────────────────────────────────────────
DB_PATH = ROOT_DIR / "trust_soc.db"

# ─────────────────────────────────────────
# API (FastAPI)
# ─────────────────────────────────────────
API_HOST = "127.0.0.1"
API_PORT = 8000
CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# ─────────────────────────────────────────
# Feature Columns to Drop (Leakage / Identifiers / Constants)
# ─────────────────────────────────────────
DROP_COLUMNS = [
    # Identifiers & Metadata (Target Leakage / Non-generalizable)
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
    "Source Port",
    "Destination Port",
    "Protocol",
    # Duplicate column in CICFlowMeter
    "Fwd Header Length.1",
    # Constant columns (zero variance across all 2.8M rows)
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
]
