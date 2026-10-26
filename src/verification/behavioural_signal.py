"""
Signal (c): Behavioural Baseline Check (b)
==========================================
Maintains host profiles computed from benign training traffic and a causal
rolling window of recent host activity to evaluate if an alerted flow deviates
from the host's own historical baseline.

Strictly adheres to Section 4.2(c) and Section 11 (Milestone 2) specifications.
Does NOT inspect ground_truth or Detection Agent probability p_d.
Maintains causal integrity (rolling window updates strictly AFTER scoring).
"""

import logging
from collections import deque
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import numpy as np
import pandas as pd
import joblib

from src.config.config import (
    PROCESSED_X_TRAIN_RAW,
    PROCESSED_TRAIN_FLOWS,
    PROCESSED_Y_TRAIN,
    BEHAVIOURAL_PROFILES_PATH,
    BEHAVIOURAL_WINDOW_SIZE,
    STRONG_CONTRADICTION_THRESHOLD,
)

log = logging.getLogger("TRUST-SOC.verification.behavioural")


def build_behavioural_profiles(
    x_raw_path: Path = PROCESSED_X_TRAIN_RAW,
    train_meta_path: Path = PROCESSED_TRAIN_FLOWS,
    y_train_path: Path = PROCESSED_Y_TRAIN,
    save_path: Path = BEHAVIOURAL_PROFILES_PATH,
    min_flows_per_host: int = 10,
) -> Dict[str, Any]:
    """
    Computes host baseline profiles strictly from benign training flows.
    """
    log.info("Loading training data for behavioural profiles...")
    train_meta = joblib.load(train_meta_path)
    X_raw = joblib.load(x_raw_path)
    y_train = joblib.load(y_train_path)

    # Benign only
    benign_mask = (y_train == 0)
    benign_meta = train_meta[benign_mask]
    benign_X = X_raw[benign_mask]

    tracked_metrics = ["Flow Packets/s", "Flow Bytes/s", "Flow Duration", "Packet Length Mean"]

    # Global benign baseline fallback
    global_profile = {}
    for metric in tracked_metrics:
        vals = benign_X[metric].to_numpy(dtype=np.float32)
        mean_v = float(np.mean(vals))
        std_v = float(np.std(vals))
        if std_v <= 0:
            std_v = 1.0
        p95_v = float(np.percentile(vals, 95))
        global_profile[metric] = {"mean": mean_v, "std": std_v, "p95": p95_v}

    # Host-specific baselines
    src_ips = benign_meta["Source IP"].to_numpy()
    unique_hosts, host_counts = np.unique(src_ips, return_counts=True)
    frequent_hosts = unique_hosts[host_counts >= min_flows_per_host]

    host_profiles = {}
    for host in frequent_hosts:
        h_mask = (src_ips == host)
        h_X = benign_X[h_mask]
        h_prof = {}
        for metric in tracked_metrics:
            vals = h_X[metric].to_numpy(dtype=np.float32)
            m_val = float(np.mean(vals))
            s_val = float(np.std(vals))
            if s_val <= 0:
                s_val = 1.0
            p95_val = float(np.percentile(vals, 95))
            h_prof[metric] = {"mean": m_val, "std": s_val, "p95": p95_val}
        host_profiles[str(host)] = h_prof

    log.info(f"Built behavioural baselines for {len(host_profiles)} frequent hosts + global fallback.")

    artefact = {
        "global_profile": global_profile,
        "host_profiles": host_profiles,
        "tracked_metrics": tracked_metrics,
        "trained_on": "Benign flows only (CICIDS2017 training split)",
    }

    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artefact, save_path)
    log.info(f"Saved behavioural profiles to {save_path}")
    return artefact


class BehaviouralVerifier:
    """
    Evaluates flow deviation relative to the host's historical benign baseline
    and maintains a causal rolling window of recent host traffic.
    """

    def __init__(
        self,
        profiles_path: Path = BEHAVIOURAL_PROFILES_PATH,
        window_size: int = BEHAVIOURAL_WINDOW_SIZE,
        strong_contra_thresh: float = STRONG_CONTRADICTION_THRESHOLD,
    ):
        self.strong_contra_thresh = strong_contra_thresh
        self.window_size = window_size

        if not profiles_path.exists():
            log.warning(f"Behavioural profiles not found at {profiles_path}. Building now...")
            self.artefact = build_behavioural_profiles(save_path=profiles_path)
        else:
            self.artefact = joblib.load(profiles_path)

        self.global_profile = self.artefact["global_profile"]
        self.host_profiles = self.artefact["host_profiles"]
        self.tracked_metrics = self.artefact["tracked_metrics"]

        # Causal rolling windows per host (Source IP -> deque)
        self.rolling_windows: Dict[str, deque] = {}

    def reset_windows(self):
        """Clears rolling windows for fresh simulation or evaluation passes."""
        self.rolling_windows.clear()

    def verify_flow(
        self,
        flow_metadata: Dict[str, Any],
        flow_features: Dict[str, Any],
        update_window: bool = True,
    ) -> Dict[str, Any]:
        """
        Computes behavioural deviation score b in [0, 1].

        CAUSAL INTEGRITY:
        The score is computed on the host's state BEFORE appending the current flow.
        If update_window is True, the flow is appended to the rolling window AFTER scoring.

        Args:
            flow_metadata: Dict with Source IP, Destination IP, etc.
            flow_features: Dict with unscaled flow features (Flow Packets/s, Flow Bytes/s, etc.)
            update_window: Whether to causally update the rolling window after scoring.

        Returns:
            Dict conforming to common signal contract:
            {"score": float, "strongly_contradictory": bool, "details": dict}
        """
        src_ip = str(flow_metadata.get("Source IP", "")).strip()

        # Select profile (host-specific if available, else global)
        if src_ip in self.host_profiles:
            profile = self.host_profiles[src_ip]
            profile_type = "host_specific"
        else:
            profile = self.global_profile
            profile_type = "global_benign_fallback"

        # 1. Compute per-metric Z-deviations for the current flow
        deviations = []
        metric_details = {}

        for metric in self.tracked_metrics:
            val = float(flow_features.get(metric, 0.0))
            stat = profile.get(metric, {"mean": 0.0, "std": 1.0, "p95": 1.0})
            mean = stat["mean"]
            std = stat["std"] if stat["std"] > 0 else 1.0

            # Normalized positive deviation (excess beyond normal mean)
            diff = max(0.0, val - mean)
            # Deviation normalized by 3 standard deviations (Z=3 maps to ~1.0)
            norm_dev = min(1.0, diff / (3.0 * std))
            deviations.append(norm_dev)
            metric_details[metric] = {
                "observed": round(val, 2),
                "baseline_mean": round(mean, 2),
                "normalized_deviation": round(norm_dev, 4),
            }

        flow_dev = float(np.mean(deviations))

        # 2. Check rolling window for recent activity bursts
        window = self.rolling_windows.get(src_ip)
        if window and len(window) >= 3:
            # Average deviation across recent flows
            recent_devs = [item["flow_dev"] for item in window]
            rolling_dev = float(np.mean(recent_devs))
            window_len = len(window)
        else:
            rolling_dev = flow_dev
            window_len = len(window) if window else 0

        # Fused behavioural score: 70% current flow deviation + 30% rolling window trend
        score = 0.70 * flow_dev + 0.30 * rolling_dev
        score = max(0.0, min(1.0, float(score)))

        interpretation = (
            f"Behavioural surge detected ({profile_type}) - corroborates attack"
            if score >= 0.50
            else f"Traffic conforms to {profile_type} historical baseline - contradicts attack"
        )

        details = {
            "profile_type": profile_type,
            "host": src_ip,
            "rolling_window_depth": window_len,
            "flow_deviation": round(flow_dev, 4),
            "rolling_deviation": round(rolling_dev, 4),
            "metric_breakdown": metric_details,
            "interpretation": interpretation,
        }

        # 3. Causal window update strictly AFTER scoring
        if update_window:
            if src_ip not in self.rolling_windows:
                self.rolling_windows[src_ip] = deque(maxlen=self.window_size)
            self.rolling_windows[src_ip].append({
                "flow_dev": flow_dev,
                "timestamp": flow_metadata.get("Timestamp", ""),
            })

        return {
            "score": round(score, 4),
            "strongly_contradictory": score < self.strong_contra_thresh,
            "details": details,
        }
