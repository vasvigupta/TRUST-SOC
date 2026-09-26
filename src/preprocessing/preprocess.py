"""
TRUST-SOC Preprocessing Pipeline
==================================
Stage 2: Reproducible, leakage-free preprocessing.

Data Leakage Prevention
------------------------
- Scaler is fitted ONLY on X_train.
- Label encoder is fitted ONLY on training labels.
- Resampling (if any) is applied ONLY on training data.
- Test set is never touched until final evaluation.
- Processed splits are saved separately so replay/predict
  always loads the same scaler/encoder used at training time.
"""

import sys
import logging
import warnings
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

warnings.filterwarnings("ignore")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("TRUST-SOC.preprocess")

# Local imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.config.config import (
    RAW_DIR, PROC_DIR, MODELS_DIR,
    LABEL_MAPPING, DROP_COLUMNS,
    TEST_SIZE, VALIDATION_SIZE, RANDOM_STATE,
    SCALER_PATH, ENCODER_PATH, FEATURE_NAMES_PATH,
    PROCESSED_X_TRAIN, PROCESSED_X_VAL, PROCESSED_X_TEST,
    PROCESSED_Y_TRAIN, PROCESSED_Y_VAL, PROCESSED_Y_TEST,
)


# ─────────────────────────────────────────────────────────────────
# 1. LOADING
# ─────────────────────────────────────────────────────────────────

def load_cicids2017(raw_dir: Path = RAW_DIR) -> pd.DataFrame:
    """Load and concatenate all CICIDS2017 CSV files."""
    csv_files = sorted(raw_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"ERROR: CICIDS2017 dataset not found at {raw_dir}\n"
            "Place the CSV files there and re-run."
        )

    log.info(f"Found {len(csv_files)} CSV file(s): {[f.name for f in csv_files]}")
    frames = []
    for f in csv_files:
        log.info(f"  Loading {f.name}  ({f.stat().st_size / 1e6:.1f} MB)…")
        df = pd.read_csv(f, encoding="utf-8", low_memory=False)
        df.columns = df.columns.str.strip()   # strip whitespace from column names
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    log.info(f"Combined shape: {combined.shape}")
    return combined


# ─────────────────────────────────────────────────────────────────
# 2. LABEL INSPECTION & MAPPING
# ─────────────────────────────────────────────────────────────────

def find_label_column(df: pd.DataFrame) -> str:
    """Return the column name used for labels (robust to leading spaces)."""
    candidates = [c for c in df.columns if c.strip().lower() == "label"]
    if not candidates:
        raise KeyError(
            "ERROR: Required feature columns are missing. "
            "Cannot find a 'Label' column in the dataset."
        )
    return candidates[0]


def inspect_labels(df: pd.DataFrame) -> pd.Series:
    """Log original label distribution."""
    label_col = find_label_column(df)
    counts = df[label_col].value_counts()
    log.info("─" * 60)
    log.info("ORIGINAL CICIDS2017 LABELS:")
    for lbl, cnt in counts.items():
        log.info(f"  {lbl:<45} {cnt:>8,}")
    log.info("─" * 60)
    return counts


def apply_label_mapping(df: pd.DataFrame, mapping: dict = LABEL_MAPPING) -> pd.DataFrame:
    """Map raw CICIDS2017 labels → TRUST-SOC six classes."""
    label_col = find_label_column(df)
    original_labels = df[label_col].unique()

    # Warn about unmapped labels
    unmapped = [l for l in original_labels if l not in mapping]
    if unmapped:
        log.warning(f"Unmapped labels (will be DROPPED): {unmapped}")

    df = df.copy()
    df["TrustSOC_Label"] = df[label_col].map(mapping)

    # Drop rows with unmapped labels
    before = len(df)
    df = df.dropna(subset=["TrustSOC_Label"])
    after = len(df)
    if before != after:
        log.warning(f"Dropped {before - after:,} rows with unmapped labels.")

    log.info("TRUST-SOC label distribution after mapping:")
    for lbl, cnt in df["TrustSOC_Label"].value_counts().items():
        log.info(f"  {lbl:<20} {cnt:>8,}")

    return df


# ─────────────────────────────────────────────────────────────────
# 3. CLEANING
# ─────────────────────────────────────────────────────────────────

def clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    Full cleaning pipeline:
    - Strip column names
    - Drop explicit non-feature columns
    - Remove duplicates
    - Replace inf with NaN
    - Drop rows with NaN in feature columns
    - Remove constant (zero-variance) columns
    """
    log.info("Starting cleaning…")
    log.info(f"  Shape before cleaning: {df.shape}")

    # Drop known non-feature columns (label columns, IPs, timestamps…)
    cols_to_drop = [c for c in DROP_COLUMNS if c in df.columns]
    # Also drop original label column if different name
    label_col = find_label_column(df) if any(
        c.strip().lower() == "label" for c in df.columns
    ) else None
    if label_col and label_col not in cols_to_drop:
        cols_to_drop.append(label_col)

    df = df.drop(columns=cols_to_drop, errors="ignore")
    log.info(f"  After dropping metadata cols: {df.shape}")

    # Keep TrustSOC_Label separate
    target = df.pop("TrustSOC_Label")

    # Duplicates
    n_dup = df.duplicated().sum()
    log.info(f"  Duplicate rows: {n_dup:,}")
    df = df.drop_duplicates()
    target = target.loc[df.index]
    log.info(f"  After dedup: {df.shape}")

    # Infinite values → NaN
    n_inf = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
    log.info(f"  Infinite values: {n_inf:,}")
    df = df.replace([np.inf, -np.inf], np.nan)

    # NaN in feature columns
    n_nan = df.isnull().sum().sum()
    log.info(f"  NaN values: {n_nan:,}")
    df = df.dropna()
    target = target.loc[df.index]
    log.info(f"  After NaN drop: {df.shape}")

    # Constant columns (zero variance)
    numeric_df = df.select_dtypes(include=[np.number])
    const_cols = numeric_df.columns[numeric_df.std() == 0].tolist()
    log.info(f"  Constant columns removed: {const_cols}")
    df = df.drop(columns=const_cols, errors="ignore")

    # Non-numeric columns
    non_numeric = df.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric:
        log.warning(f"  Non-numeric columns dropped: {non_numeric}")
        df = df.drop(columns=non_numeric)

    df["TrustSOC_Label"] = target.values
    log.info(f"  Shape after full cleaning: {df.shape}")
    return df


# ─────────────────────────────────────────────────────────────────
# 4. SPLIT
# ─────────────────────────────────────────────────────────────────

def split_data(df: pd.DataFrame):
    """Stratified train / validation / test split (70/15/15)."""
    X = df.drop(columns=["TrustSOC_Label"])
    y = df["TrustSOC_Label"]

    # Step 1: hold out test set (15% of total)
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    # Step 2: split remaining into train / val (~85% → 70/15)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp,
        test_size=VALIDATION_SIZE,
        stratify=y_temp,
        random_state=RANDOM_STATE,
    )

    log.info(f"  Train:      {X_train.shape[0]:>8,} rows")
    log.info(f"  Validation: {X_val.shape[0]:>8,} rows")
    log.info(f"  Test:       {X_test.shape[0]:>8,} rows")
    return X_train, X_val, X_test, y_train, y_val, y_test


# ─────────────────────────────────────────────────────────────────
# 5. SCALING  (fit on train only → transform val/test)
# ─────────────────────────────────────────────────────────────────

def scale(X_train, X_val, X_test):
    """StandardScaler fitted ONLY on training data. Leakage-safe."""
    scaler = StandardScaler()
    X_train_s = pd.DataFrame(
        scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index
    )
    X_val_s = pd.DataFrame(
        scaler.transform(X_val), columns=X_val.columns, index=X_val.index
    )
    X_test_s = pd.DataFrame(
        scaler.transform(X_test), columns=X_test.columns, index=X_test.index
    )
    return X_train_s, X_val_s, X_test_s, scaler


# ─────────────────────────────────────────────────────────────────
# 6. ENCODE LABELS
# ─────────────────────────────────────────────────────────────────

def encode_labels(y_train, y_val, y_test):
    """LabelEncoder fitted ONLY on training labels. Leakage-safe."""
    le = LabelEncoder()
    y_train_e = le.fit_transform(y_train)
    y_val_e   = le.transform(y_val)
    y_test_e  = le.transform(y_test)
    log.info(f"  Label classes: {list(le.classes_)}")
    return y_train_e, y_val_e, y_test_e, le


# ─────────────────────────────────────────────────────────────────
# 7. SAVE PROCESSED DATA
# ─────────────────────────────────────────────────────────────────

def save_splits(X_train, X_val, X_test, y_train, y_val, y_test):
    PROC_DIR.mkdir(parents=True, exist_ok=True)
    X_train.to_parquet(PROCESSED_X_TRAIN, index=False)
    X_val.to_parquet(PROCESSED_X_VAL,   index=False)
    X_test.to_parquet(PROCESSED_X_TEST,  index=False)
    pd.Series(y_train, name="label").to_frame().to_parquet(PROCESSED_Y_TRAIN, index=False)
    pd.Series(y_val,   name="label").to_frame().to_parquet(PROCESSED_Y_VAL,   index=False)
    pd.Series(y_test,  name="label").to_frame().to_parquet(PROCESSED_Y_TEST,  index=False)
    log.info("Processed splits saved to data/processed/")


def save_artifacts(scaler, encoder, feature_names):
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler,        SCALER_PATH)
    joblib.dump(encoder,       ENCODER_PATH)
    joblib.dump(feature_names, FEATURE_NAMES_PATH)
    log.info("Scaler / encoder / feature names saved to models/")


# ─────────────────────────────────────────────────────────────────
# 8. LOAD PROCESSED DATA (for training / evaluation)
# ─────────────────────────────────────────────────────────────────

def load_splits():
    """Load saved processed splits (after preprocessing was run once)."""
    for p in [PROCESSED_X_TRAIN, PROCESSED_X_TEST, PROCESSED_Y_TRAIN, PROCESSED_Y_TEST]:
        if not p.exists():
            raise FileNotFoundError(
                f"ERROR: Processed data not found at {p}.\n"
                "Run preprocessing first:  python -m src.preprocessing.preprocess"
            )
    X_train = pd.read_parquet(PROCESSED_X_TRAIN)
    X_val   = pd.read_parquet(PROCESSED_X_VAL)
    X_test  = pd.read_parquet(PROCESSED_X_TEST)
    y_train = pd.read_parquet(PROCESSED_Y_TRAIN)["label"].values
    y_val   = pd.read_parquet(PROCESSED_Y_VAL)["label"].values
    y_test  = pd.read_parquet(PROCESSED_Y_TEST)["label"].values
    return X_train, X_val, X_test, y_train, y_val, y_test


# ─────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────

def run_preprocessing():
    log.info("=" * 60)
    log.info("TRUST-SOC  |  Preprocessing Pipeline")
    log.info("=" * 60)

    # 1. Load
    df = load_cicids2017()

    # 2. Inspect labels BEFORE mapping
    inspect_labels(df)

    # 3. Map labels
    df = apply_label_mapping(df)

    # 4. Clean
    df = clean(df)

    # 5. Split
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(df)

    # 6. Scale (train-fit only)
    X_train_s, X_val_s, X_test_s, scaler = scale(X_train, X_val, X_test)

    # 7. Encode labels (train-fit only)
    y_train_e, y_val_e, y_test_e, encoder = encode_labels(y_train, y_val, y_test)

    # 8. Save everything
    save_splits(X_train_s, X_val_s, X_test_s, y_train_e, y_val_e, y_test_e)
    save_artifacts(scaler, encoder, list(X_train_s.columns))

    # 9. Save a small replay sample (raw-scaled, from test set)
    SAMPLE_DIR = RAW_DIR.parent.parent / "sample"
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    sample = X_test_s.copy()
    sample["TrustSOC_Label"] = y_test_e
    sample_path = SAMPLE_DIR / "replay_sample.csv"
    sample.head(200).to_csv(sample_path, index=False)
    log.info(f"Replay sample (200 rows) saved → {sample_path}")

    log.info("=" * 60)
    log.info("Preprocessing COMPLETE.")
    log.info("=" * 60)


if __name__ == "__main__":
    run_preprocessing()
