"""
TRUST-SOC Preprocessing Pipeline (Stage 1.3)
============================================
Handles:
1. Memory-safe chunked extraction and stratified sampling across all 8 daily CSVs.
2. Label mapping to the 6 locked project classes (excluding rare Infiltration & Heartbleed).
3. Leakage prevention: drops Flow ID, IPs, ports, timestamps, and constant columns from features.
4. Preserves unscaled feature values and flow metadata for operational alerts and evidence reports.
5. Strict stratified 70/15/15 train/val/test split (seed=42).
6. Median imputer and StandardScaler fitted on TRAIN SPLIT ONLY (zero data leakage).
7. Zero-overlap assertions between train, validation, and test splits.
"""

import os
import json
import logging
from pathlib import Path
from collections import Counter
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer

from src.config.config import (
    RAW_DIR, PROC_DIR, SAMPLE_DIR, MODELS_DIR, REPORTS_DIR,
    RANDOM_STATE, TEST_SIZE, VALIDATION_SIZE,
    PROJECT_CLASSES, SAMPLING_TARGETS, DROP_COLUMNS,
    PROCESSED_X_TRAIN, PROCESSED_X_VAL, PROCESSED_X_TEST,
    PROCESSED_Y_TRAIN, PROCESSED_Y_VAL, PROCESSED_Y_TEST,
    PROCESSED_X_TEST_RAW, PROCESSED_TEST_FLOWS,
    SCALER_PATH, IMPUTER_PATH, ENCODER_PATH, FEATURE_NAMES_PATH,
    REPLAY_SAMPLE_PATH
)
from src.preprocessing.label_mapping import map_raw_label

log = logging.getLogger("TRUST-SOC.preprocess")


def run_preprocessing():
    """
    Executes the complete preprocessing pipeline end-to-end.
    """
    PROC_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    log.info("Starting Stage 1.3 Preprocessing Pipeline...")

    # 1. Chunked ingestion and stratified reservoir sampling
    raw_files = sorted(list(RAW_DIR.glob("*.csv")))
    if not raw_files:
        raise FileNotFoundError(f"ERROR: No raw CSVs found in {RAW_DIR}. Run explore stage first.")

    collected_dfs = []
    class_tallies = Counter()
    total_raw_rows_inspected = 0
    total_excluded_rows = 0

    log.info(f"Target sampling quotas per class: {SAMPLING_TARGETS}")

    for fpath in raw_files:
        fname = fpath.name
        log.info(f"Ingesting flows from {fname}...")

        chunk_iter = pd.read_csv(
            fpath,
            chunksize=100_000,
            encoding="cp1252",
            low_memory=False
        )

        for chunk in chunk_iter:
            total_raw_rows_inspected += len(chunk)

            # Strip whitespace from column names
            chunk.columns = [c.strip() for c in chunk.columns]

            # Drop UNB padding lines (where Label is NaN)
            if "Label" not in chunk.columns:
                continue
            chunk = chunk.dropna(subset=["Label"]).copy()

            # Map labels to 6 project classes
            mapped_classes = []
            valid_indices = []

            for idx, raw_lbl in zip(chunk.index, chunk["Label"]):
                mapped = map_raw_label(raw_lbl)
                if mapped is not None:
                    mapped_classes.append(mapped)
                    valid_indices.append(idx)
                else:
                    total_excluded_rows += 1

            if not valid_indices:
                continue

            chunk = chunk.loc[valid_indices].copy()
            chunk["project_class"] = mapped_classes

            # Reservoir sampling per class to hit target quotas without bias
            selected_subsets = []
            for p_cls in PROJECT_CLASSES:
                cls_df = chunk[chunk["project_class"] == p_cls]
                if cls_df.empty:
                    continue

                needed = SAMPLING_TARGETS[p_cls] - class_tallies[p_cls]
                if needed <= 0:
                    continue

                if len(cls_df) <= needed:
                    take_df = cls_df
                else:
                    take_df = cls_df.sample(n=needed, random_state=RANDOM_STATE)

                selected_subsets.append(take_df)
                class_tallies[p_cls] += len(take_df)

            if selected_subsets:
                batch_df = pd.concat(selected_subsets, ignore_index=True)
                batch_df["source_file"] = fname
                collected_dfs.append(batch_df)

        log.info(f"  Current tallies: {dict(class_tallies)}")

    df_full = pd.concat(collected_dfs, ignore_index=True)
    log.info(f"Total sampled dataset size: {len(df_full):,} flows")
    log.info(f"Sampled class distribution:\n{df_full['project_class'].value_counts()}")

    # 2. Extract flow metadata block (preserved for log replay & evidence reports)
    metadata_cols = [
        "source_file", "Flow ID", "Source IP", "Source Port",
        "Destination IP", "Destination Port", "Protocol", "Timestamp",
        "Label", "project_class"
    ]
    existing_meta = [c for c in metadata_cols if c in df_full.columns]
    flow_metadata = df_full[existing_meta].copy()

    # 3. Separate features and target (convert explicitly to standard numpy arrays)
    y_raw = np.array(df_full["project_class"].to_list(), dtype=str)

    # Drop non-feature columns
    cols_to_drop = [c for c in DROP_COLUMNS if c in df_full.columns]
    cols_to_drop += ["project_class", "Label", "source_file"]
    cols_to_drop = list(set(cols_to_drop))

    X_raw_df = df_full.drop(columns=cols_to_drop).copy()
    feature_names = list(X_raw_df.columns)
    log.info(f"Number of statistical feature columns: {len(feature_names)}")

    # Replace inf with nan before converting to numpy
    X_raw_df = X_raw_df.replace([np.inf, -np.inf], np.nan)
    X_raw_np = X_raw_df.to_numpy(dtype=np.float32)

    # 4. Stratified Train / Validation / Test Split (70% / 15% / 15%)
    indices = np.arange(len(df_full), dtype=np.int64)

    # First split: 85% train_val, 15% test
    train_val_idx, test_idx, y_train_val, y_test = train_test_split(
        indices,
        y_raw,
        test_size=TEST_SIZE,
        stratify=y_raw,
        random_state=RANDOM_STATE
    )

    # Second split: train_val into 70% train and 15% validation of total
    train_idx, val_idx, y_train, y_val = train_test_split(
        train_val_idx,
        y_train_val,
        test_size=VALIDATION_SIZE,
        stratify=y_train_val,
        random_state=RANDOM_STATE
    )

    # Assert zero leakage between splits
    overlap_train_val = set(train_idx).intersection(set(val_idx))
    overlap_train_test = set(train_idx).intersection(set(test_idx))
    overlap_val_test = set(val_idx).intersection(set(test_idx))
    assert len(overlap_train_val) == 0, "DATA LEAKAGE: Overlap between Train and Validation!"
    assert len(overlap_train_test) == 0, "DATA LEAKAGE: Overlap between Train and Test!"
    assert len(overlap_val_test) == 0, "DATA LEAKAGE: Overlap between Validation and Test!"
    log.info("Zero split overlap verified: Train ∩ Val = 0, Train ∩ Test = 0, Val ∩ Test = 0")

    log.info(f"Split sizes: Train={len(train_idx):,} ({len(train_idx)/len(indices):.1%}), "
             f"Val={len(val_idx):,} ({len(val_idx)/len(indices):.1%}), "
             f"Test={len(test_idx):,} ({len(test_idx)/len(indices):.1%})")

    X_train_raw = X_raw_np[train_idx]
    X_val_raw   = X_raw_np[val_idx]
    X_test_raw  = X_raw_np[test_idx]

    # 5. Handle Missing Values / Median Imputation (Fitted on Train Split Only)
    imputer = SimpleImputer(strategy="median")
    log.info("Fitting SimpleImputer(strategy='median') on TRAIN split only...")
    X_train_imp = imputer.fit_transform(X_train_raw).astype(np.float32)
    X_val_imp   = imputer.transform(X_val_raw).astype(np.float32)
    X_test_imp  = imputer.transform(X_test_raw).astype(np.float32)

    from src.config.config import (
        PROCESSED_X_TRAIN_RAW, PROCESSED_X_VAL_RAW,
        PROCESSED_TRAIN_FLOWS, PROCESSED_VAL_FLOWS
    )

    # Keep unscaled values for test, val, and train flows
    X_train_unscaled = pd.DataFrame(X_train_imp, columns=feature_names)
    X_val_unscaled   = pd.DataFrame(X_val_imp, columns=feature_names)
    X_test_unscaled  = pd.DataFrame(X_test_imp, columns=feature_names)

    # 6. Feature Scaling (StandardScaler fitted on TRAIN split only)
    scaler = StandardScaler()
    log.info("Fitting StandardScaler on TRAIN split only...")
    X_train_scaled = scaler.fit_transform(X_train_imp).astype(np.float32)
    X_val_scaled   = scaler.transform(X_val_imp).astype(np.float32)
    X_test_scaled  = scaler.transform(X_test_imp).astype(np.float32)

    # 7. Encode Labels
    encoder = LabelEncoder()
    encoder.fit(PROJECT_CLASSES)
    y_train_enc = encoder.transform(y_train).astype(np.int32)
    y_val_enc   = encoder.transform(y_val).astype(np.int32)
    y_test_enc  = encoder.transform(y_test).astype(np.int32)

    log.info("Class encoding mapping:")
    for cls_name, cls_idx in zip(encoder.classes_, range(len(encoder.classes_))):
        log.info(f"  {cls_idx} -> {cls_name}")

    # 8. Persist Processed Artifacts
    log.info("Saving processed artifacts to disk...")
    joblib.dump(X_train_scaled, PROCESSED_X_TRAIN, compress=3)
    joblib.dump(y_train_enc,    PROCESSED_Y_TRAIN, compress=3)
    joblib.dump(X_val_scaled,   PROCESSED_X_VAL,   compress=3)
    joblib.dump(y_val_enc,      PROCESSED_Y_VAL,   compress=3)
    joblib.dump(X_test_scaled,  PROCESSED_X_TEST,  compress=3)
    joblib.dump(y_test_enc,     PROCESSED_Y_TEST,  compress=3)

    joblib.dump(X_train_unscaled, PROCESSED_X_TRAIN_RAW, compress=3)
    joblib.dump(X_val_unscaled,   PROCESSED_X_VAL_RAW,   compress=3)
    joblib.dump(X_test_unscaled,  PROCESSED_X_TEST_RAW,  compress=3)

    joblib.dump(flow_metadata.iloc[train_idx].reset_index(drop=True), PROCESSED_TRAIN_FLOWS, compress=3)
    joblib.dump(flow_metadata.iloc[val_idx].reset_index(drop=True),   PROCESSED_VAL_FLOWS,   compress=3)
    joblib.dump(flow_metadata.iloc[test_idx].reset_index(drop=True),  PROCESSED_TEST_FLOWS,  compress=3)

    joblib.dump(scaler,        SCALER_PATH)
    joblib.dump(imputer,       IMPUTER_PATH)
    joblib.dump(encoder,       ENCODER_PATH)
    joblib.dump(feature_names, FEATURE_NAMES_PATH)

    # Create small replay sample CSV for quick CLI demos
    test_meta = flow_metadata.iloc[test_idx].reset_index(drop=True)
    replay_sample = pd.concat([test_meta, X_test_unscaled], axis=1)
    replay_head = replay_sample.groupby("project_class", group_keys=False).apply(
        lambda g: g.sample(min(len(g), 200), random_state=RANDOM_STATE)
    )
    replay_head.to_csv(REPLAY_SAMPLE_PATH, index=False)
    log.info(f"Saved replay sample CSV ({len(replay_head)} rows) to {REPLAY_SAMPLE_PATH}")

    # 9. Preprocessing Summary Report
    train_dist = {cls: int(cnt) for cls, cnt in zip(*np.unique(y_train, return_counts=True))}
    val_dist   = {cls: int(cnt) for cls, cnt in zip(*np.unique(y_val, return_counts=True))}
    test_dist  = {cls: int(cnt) for cls, cnt in zip(*np.unique(y_test, return_counts=True))}

    report = {
        "pipeline_stage": "Stage 1.3 Preprocessing",
        "random_state": RANDOM_STATE,
        "total_raw_rows_inspected": total_raw_rows_inspected,
        "total_excluded_rows": total_excluded_rows,
        "total_processed_samples": len(df_full),
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "dropped_columns": cols_to_drop,
        "split_sizes": {
            "train": len(train_idx),
            "val": len(val_idx),
            "test": len(test_idx),
        },
        "class_distributions": {
            "train": train_dist,
            "val": val_dist,
            "test": test_dist,
        },
        "leakage_checks": {
            "train_val_overlap": 0,
            "train_test_overlap": 0,
            "val_test_overlap": 0,
            "scaler_fitted_on": "train_only",
            "imputer_fitted_on": "train_only",
        }
    }

    report_path = REPORTS_DIR / "preprocessing_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    log.info(f"Saved preprocessing report to {report_path}")

    log.info("Stage 1.3 Preprocessing completed successfully.")
    return report


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_preprocessing()
