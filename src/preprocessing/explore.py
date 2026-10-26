"""
TRUST-SOC Data Exploration Module (Stage 1.1)
==============================================
Chunked exploration of CICIDS2017 daily CSV files.
Memory-safe: uses streaming chunked reads to operate within strict RAM constraints.
Generates:
- exploration_summary.json (raw statistics)
- missing_values_summary.txt (formatted report)
- class_distribution.png (light theme visualization)
"""

import os
import json
import logging
from pathlib import Path
from collections import Counter
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from src.config.config import RAW_DIR, RESULTS_DIR, REPORTS_DIR
from src.config.theme import THEME, apply_matplotlib_theme

log = logging.getLogger("TRUST-SOC.explore")

CHUNK_SIZE = 100_000


def explore_dataset(raw_dir: Path = RAW_DIR) -> dict:
    """
    Performs chunked exploration of all CICIDS2017 CSV files.
    Returns comprehensive summary dict.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(list(raw_dir.glob("*.csv")))
    if not csv_files:
        raise FileNotFoundError(f"ERROR: No CSV files found in {raw_dir}")

    log.info(f"Discovered {len(csv_files)} CSV files in {raw_dir}")

    total_raw_rows = 0
    total_valid_rows = 0
    total_blank_padding_rows = 0

    per_file_stats = {}
    overall_label_counts = Counter()
    missing_counts = Counter()
    inf_counts = Counter()
    column_mins = {}
    column_maxs = {}
    reference_columns = None
    column_name_variants = {}

    for file_path in csv_files:
        fname = file_path.name
        fsize_mb = round(file_path.stat().st_size / (1024 * 1024), 2)
        log.info(f"Scanning {fname} ({fsize_mb} MB)...")

        file_raw_rows = 0
        file_valid_rows = 0
        file_blank_rows = 0
        file_labels = Counter()

        # Read in chunks to avoid OOM
        # Note: CICIDS2017 files can have latin1 / cp1252 characters in Web Attack labels
        chunk_iter = pd.read_csv(
            file_path,
            chunksize=CHUNK_SIZE,
            encoding="cp1252",
            low_memory=False
        )

        for chunk_idx, chunk in enumerate(chunk_iter):
            file_raw_rows += len(chunk)
            total_raw_rows += len(chunk)

            raw_cols = list(chunk.columns)
            stripped_cols = [c.strip() for c in raw_cols]

            if reference_columns is None:
                reference_columns = stripped_cols
                for r, s in zip(raw_cols, stripped_cols):
                    column_name_variants[s] = r

            # Identify label column (usually 'Label' or ' Label')
            label_col = None
            for c in raw_cols:
                if c.strip().lower() == "label":
                    label_col = c
                    break

            # Filter completely empty / padding lines (known UNB dataset quirk in Thursday-WebAttacks)
            is_blank = chunk[label_col].isna() if label_col else chunk.isna().all(axis=1)
            n_blank = int(is_blank.sum())
            file_blank_rows += n_blank
            total_blank_padding_rows += n_blank

            valid_chunk = chunk[~is_blank]
            file_valid_rows += len(valid_chunk)
            total_valid_rows += len(valid_chunk)

            if len(valid_chunk) == 0:
                continue

            if label_col:
                for lbl, cnt in valid_chunk[label_col].value_counts().items():
                    lbl_str = str(lbl).strip()
                    file_labels[lbl_str] += cnt
                    overall_label_counts[lbl_str] += cnt

            # Check missing and inf values on valid rows
            for col in raw_cols:
                s_col = col.strip()
                n_miss = int(valid_chunk[col].isna().sum())
                if n_miss > 0:
                    missing_counts[s_col] += n_miss

                # Numeric infinite values
                if pd.api.types.is_numeric_dtype(valid_chunk[col]):
                    n_inf = int(np.isinf(valid_chunk[col]).sum())
                    if n_inf > 0:
                        inf_counts[s_col] += n_inf

                    # Min/Max tracking for constant columns check
                    clean_vals = valid_chunk[col].replace([np.inf, -np.inf], np.nan).dropna()
                    if len(clean_vals) > 0:
                        c_min = float(clean_vals.min())
                        c_max = float(clean_vals.max())
                        if s_col not in column_mins:
                            column_mins[s_col] = c_min
                            column_maxs[s_col] = c_max
                        else:
                            column_mins[s_col] = min(column_mins[s_col], c_min)
                            column_maxs[s_col] = max(column_maxs[s_col], c_max)

        per_file_stats[fname] = {
            "size_mb": fsize_mb,
            "raw_rows": file_raw_rows,
            "valid_flows": file_valid_rows,
            "blank_padding_rows": file_blank_rows,
            "labels": dict(file_labels)
        }
        log.info(f"  -> {fname}: {file_valid_rows:,} valid flows ({file_blank_rows:,} blank rows)")

    # Detect constant columns (numeric features where min == max across entire dataset)
    constant_columns = [
        col for col, c_min in column_mins.items()
        if c_min == column_maxs.get(col) and col.lower() not in ["label", "source ip", "destination ip"]
    ]

    summary = {
        "dataset_name": "CICIDS2017 (TrafficLabelling / GeneratedLabelledFlows)",
        "total_files": len(csv_files),
        "total_raw_rows": total_raw_rows,
        "total_valid_flows": total_valid_rows,
        "total_blank_padding_rows": total_blank_padding_rows,
        "total_features": len(reference_columns) if reference_columns else 0,
        "columns_stripped": reference_columns,
        "raw_column_headers": list(column_name_variants.values()),
        "per_file_stats": per_file_stats,
        "original_labels": dict(sorted(overall_label_counts.items(), key=lambda x: -x[1])),
        "missing_values_valid_flows": dict(missing_counts),
        "infinite_values_valid_flows": dict(inf_counts),
        "constant_columns": constant_columns,
    }

    # Save summary JSON
    summary_path = REPORTS_DIR / "exploration_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    log.info(f"Saved exploration summary to {summary_path}")

    # Save text report of missing/inf values
    report_text_path = REPORTS_DIR / "missing_values_summary.txt"
    with open(report_text_path, "w", encoding="utf-8") as f:
        f.write("=" * 75 + "\n")
        f.write("TRUST-SOC: CICIDS2017 DATASET EXPLORATION & DATA QUALITY AUDIT REPORT\n")
        f.write("=" * 75 + "\n\n")
        f.write(f"Total Raw Lines in CSVs:      {total_raw_rows:,}\n")
        f.write(f"Blank / Padding Lines (UNB):  {total_blank_padding_rows:,} (in Thursday-WebAttacks)\n")
        f.write(f"Total Valid Flow Records:     {total_valid_rows:,}\n")
        f.write(f"Total Flow Columns:           {len(reference_columns)}\n")
        f.write(f"Distinct Labels Found:        {len(overall_label_counts)}\n\n")

        f.write("-" * 75 + "\n")
        f.write("PER-FILE BREAKDOWN:\n")
        f.write("-" * 75 + "\n")
        for fname, stats in per_file_stats.items():
            f.write(
                f"{fname:<50} | {stats['size_mb']:>7.2f} MB | "
                f"{stats['valid_flows']:>10,} valid flows | {stats['blank_padding_rows']:>7,} blank\n"
            )

        f.write("\n" + "-" * 75 + "\n")
        f.write("ORIGINAL LABELS DISTRIBUTION (VALID FLOW RECORDS):\n")
        f.write("-" * 75 + "\n")
        for lbl, cnt in sorted(overall_label_counts.items(), key=lambda x: -x[1]):
            pct = (cnt / total_valid_rows) * 100
            f.write(f"{lbl:<40} | {cnt:>10,} flows ({pct:>6.2f}%)\n")

        f.write("\n" + "-" * 75 + "\n")
        f.write("COLUMNS WITH MISSING (NaN) VALUES (VALID FLOW RECORDS):\n")
        f.write("-" * 75 + "\n")
        if missing_counts:
            for col, cnt in missing_counts.items():
                pct = (cnt / total_valid_rows) * 100
                f.write(f"{col:<40} | {cnt:>10,} missing ({pct:>6.4f}%)\n")
        else:
            f.write("No missing (NaN) values detected among valid flows.\n")

        f.write("\n" + "-" * 75 + "\n")
        f.write("COLUMNS WITH INFINITE (inf/-inf) VALUES (VALID FLOW RECORDS):\n")
        f.write("-" * 75 + "\n")
        if inf_counts:
            for col, cnt in inf_counts.items():
                pct = (cnt / total_valid_rows) * 100
                f.write(f"{col:<40} | {cnt:>10,} infinite ({pct:>6.4f}%)\n")
        else:
            f.write("No infinite values detected.\n")

        f.write("\n" + "-" * 75 + "\n")
        f.write(f"CONSTANT COLUMNS DETECTED (count={len(constant_columns)}):\n")
        f.write("-" * 75 + "\n")
        for col in constant_columns:
            f.write(f"  - {col} (constant value = {column_mins[col]})\n")

    log.info(f"Saved text report to {report_text_path}")

    # Generate Class Distribution Plot (Light Theme, Section 3 tokens)
    plot_path = RESULTS_DIR / "class_distribution.png"
    generate_distribution_plot(overall_label_counts, plot_path)

    return summary


def generate_distribution_plot(label_counts: Counter, output_path: Path):
    """
    Renders a clean, accessible, light-theme bar plot of raw CICIDS2017 labels.
    """
    apply_matplotlib_theme(plt)

    labels = [item[0] for item in sorted(label_counts.items(), key=lambda x: x[1])]
    counts = [item[1] for item in sorted(label_counts.items(), key=lambda x: x[1])]

    fig, ax = plt.subplots(figsize=(12, 7), facecolor=THEME["surface"])

    bars = ax.barh(labels, counts, color=THEME["primary"], edgecolor=THEME["border"], height=0.65)

    ax.set_title("CICIDS2017 Original Class Distribution (2,830,743 Valid Flows)", fontsize=13, weight="bold", pad=15, color=THEME["primary"])
    ax.set_xlabel("Number of Flow Records (Logarithmic Scale)", fontsize=11, labelpad=10, color=THEME["text"])
    ax.set_xscale("log")
    ax.grid(axis="x", linestyle="--", alpha=0.5, color=THEME["border"])
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(THEME["border"])
    ax.spines["bottom"].set_color(THEME["border"])

    # Annotate bar counts
    for bar in bars:
        width = bar.get_width()
        ax.text(
            width * 1.15,
            bar.get_y() + bar.get_height() / 2,
            f"{int(width):,}",
            va="center",
            ha="left",
            fontsize=9,
            color=THEME["text"],
            weight="medium"
        )

    plt.tight_layout()
    fig.savefig(output_path, dpi=300, facecolor=THEME["surface"], bbox_inches="tight")
    plt.close(fig)
    log.info(f"Saved class distribution plot to {output_path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    summary = explore_dataset()
    print("\n--- EXPLORATION COMPLETED SUCCESSFULLY ---")
    print(f"Total valid flows: {summary['total_valid_flows']:,}")
    print(f"Total blank rows: {summary['total_blank_padding_rows']:,}")
    print(f"Total features: {summary['total_features']}")
    print("Labels found:")
    for k, v in summary["original_labels"].items():
        print(f"  {k}: {v:,}")
