"""
TRUST-SOC Milestone 1 Prototype UI (Stage 1.10)
==============================================
Interactive Streamlit demonstration of Milestone 1 ML Pipeline:
- Dataset Summary (CICIDS2017, 6 classes, 68 features)
- Detection Agent (Random Forest Baseline + XGBoost)
- Baseline Evaluation Metrics & Reference Alert-Level FPR
- Global & Per-Prediction SHAP Explanations
- Interactive Log Replay Simulation (Flow-by-Flow Alert Generation)
"""

import os
import json
import logging
from pathlib import Path
import streamlit as st
import pandas as pd
import numpy as np

# Page configuration
st.set_page_config(
    page_title="TRUST-SOC | Milestone 1 Prototype",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom light-theme CSS tokens
st.markdown("""
<style>
    :root {
        --bg: #F7F9FC;
        --surface: #FFFFFF;
        --border: #D9E0EA;
        --text: #1F2937;
        --primary: #1F3864;
        --high: #B42318;
        --medium: #B54708;
        --low: #2E7D5B;
    }
    .metric-card {
        background-color: #FFFFFF;
        border: 1px solid #D9E0EA;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .badge-alert {
        background-color: #FEE4E2;
        color: #B42318;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 0.85em;
    }
    .badge-benign {
        background-color: #ECFDF3;
        color: #027A48;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 0.85em;
    }
    .badge-not-impl {
        background-color: #F2F4F7;
        color: #475467;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 0.85em;
    }
</style>
""", unsafe_allow_html=True)

ROOT_DIR = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT_DIR / "results"
METRICS_PATH = RESULTS_DIR / "metrics" / "detection_baseline.json"
SHAP_PLOT_PATH = RESULTS_DIR / "shap" / "shap_summary_bar.png"
CM_PLOT_PATH = RESULTS_DIR / "confusion_matrix" / "confusion_matrix.png"
CLASS_DIST_PLOT = RESULTS_DIR / "class_distribution.png"

# Header
st.title("🛡️ TRUST-SOC: Detection Pipeline Prototype")
st.markdown("**A Trust-Aware, Verification-Driven Detection Pipeline for Security Operations Centers**")
st.caption("BTech CSE Micro-Project — Milestone 1 Deliverable | Guided by Mr. Mohit Tiwari, BVCCOE")
st.divider()

# Sidebar navigation
menu = st.sidebar.radio(
    "Navigation",
    ["System Overview", "Detection Baseline & FPR", "SHAP Explainability", "Interactive Log Replay"]
)

# 1. System Overview
if menu == "System Overview":
    st.header("1. Data Foundation & Prototype Architecture")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Valid Flows", "2,830,743", "Raw Ingested")
    with col2:
        st.metric("Stratified Sample", "202,981", "Memory-Safe")
    with col3:
        st.metric("Features Extracted", "68", "Leakage-Filtered")
    with col4:
        st.metric("Project Classes", "6", "Synopsis Standard")

    st.subheader("Standardized 6-Class Mapping")
    st.markdown("""
    - **Benign**: Normal network flow activity (80.30% of dataset).
    - **DoS/DDoS**: Volumetric floods (Hulk, GoldenEye, Slowloris, Slowhttptest, DDoS).
    - **Port Scan**: Reconnaissance and port sweeping (SYN/RST scans).
    - **Brute Force**: Authentication attacks against protocol services (FTP-Patator, SSH-Patator).
    - **Web Attack**: Web application exploits (credential stuffing, XSS, SQLi).
    - **Botnet**: Ares botnet command-and-control beaconing.
    """)

    if CLASS_DIST_PLOT.exists():
        st.image(str(CLASS_DIST_PLOT), caption="CICIDS2017 Raw Class Distribution (Light Theme)", use_container_width=True)

# 2. Detection Baseline & FPR
elif menu == "Detection Baseline & FPR":
    st.header("2. Detection Agent Evaluation Scorecard")
    if METRICS_PATH.exists():
        with open(METRICS_PATH) as f:
            metrics = json.load(f)

        fpr_data = metrics["primary_alert_level_fpr"]
        mc_data = metrics["multiclass_metrics"]

        st.subheader("🎯 Primary Evaluation Metric (Section 4.5)")
        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        with kpi1:
            st.metric("Alert-Level FPR (Baseline)", fpr_data["alert_level_fpr_percentage"], "Target for M2 Reduction")
        with kpi2:
            st.metric("False Alerts (on Benign)", f"{fpr_data['benign_flows_falsely_alerted']:,}", f"out of {fpr_data['total_true_benign']:,}")
        with kpi3:
            st.metric("Test Accuracy", f"{mc_data['accuracy']*100:.2f}%")
        with kpi4:
            st.metric("Macro F1 Score", f"{mc_data['macro_f1']:.4f}")

        st.markdown(f"> **FPR Formula**: `{fpr_data['formula']}`")

        col_a, col_b = st.columns([1.2, 1])
        with col_a:
            st.subheader("Per-Class Performance Summary")
            per_class_df = pd.DataFrame(metrics["per_class"]).T
            st.dataframe(per_class_df[["support", "precision", "recall", "f1_score", "fpr_one_vs_rest"]], use_container_width=True)
        with col_b:
            st.subheader("Confusion Matrix")
            if CM_PLOT_PATH.exists():
                st.image(str(CM_PLOT_PATH), use_container_width=True)
    else:
        st.warning("Baseline metrics not found. Run: python run.py evaluate")

# 3. SHAP Explainability
elif menu == "SHAP Explainability":
    st.header("3. SHAP Feature Attribution Engine")
    st.markdown("Every detection is explained using exact `shap.TreeExplainer` Shapley attributions.")

    if SHAP_PLOT_PATH.exists():
        st.image(str(SHAP_PLOT_PATH), caption="Global Mean |SHAP| Importance Across Features", use_container_width=True)

    st.subheader("Sample Per-Prediction Explanation (JSON)")
    sample_expl_path = RESULTS_DIR / "shap" / "sample_explanation.json"
    if sample_expl_path.exists():
        with open(sample_expl_path) as f:
            sample_expl = json.load(f)
        st.json(sample_expl)
    else:
        st.info("Run: python run.py explain to generate explanations.")

# 4. Interactive Log Replay
elif menu == "Interactive Log Replay":
    st.header("4. Log Replay Simulator & Flow Ingestion")
    st.markdown("Replays held-out test flows, passes them through the Detection Agent and SHAP explainer, and outputs canonical alerts.")

    from src.ingestion.log_replay import LogReplaySimulator

    if "simulator" not in st.session_state:
        st.session_state.simulator = LogReplaySimulator(enable_shap=True)
        st.session_state.replayed_alerts = []

    c1, c2 = st.columns([1, 4])
    with c1:
        if st.button("▶️ Process Next Flow", use_container_width=True):
            alert = st.session_state.simulator.next()
            st.session_state.replayed_alerts.insert(0, alert)

        if st.button("⏩ Replay 5 Flows", use_container_width=True):
            batch = st.session_state.simulator.next_n(5)
            for b in batch:
                st.session_state.replayed_alerts.insert(0, b)

    st.subheader(f"Recent Alerts Buffer ({len(st.session_state.replayed_alerts)} replayed)")

    for alert in st.session_state.replayed_alerts[:10]:
        det = alert["detection"]
        flow = alert["flow"]
        gt = alert["ground_truth"]
        badge_cls = "badge-alert" if det["is_alert"] else "badge-benign"

        with st.expander(f"[{det['predicted_class']}] {alert['alert_id']} — Ingested at {alert['ingested_at'][:19]}"):
            col_x, col_y = st.columns(2)
            with col_x:
                st.markdown(f"**Predicted Class**: `{det['predicted_class']}` <span class='{badge_cls}'>{det['predicted_class'].upper()}</span>", unsafe_allow_html=True)
                st.markdown(f"**Confidence**: `{det['probability']:.4f}`")
                st.markdown(f"**Ground Truth**: `{gt['project_class']}` *(Original: {gt['original_label']})*")
                st.markdown(f"**Verification Status**: <span class='badge-not-impl'>NOT_IMPLEMENTED (M1)</span>", unsafe_allow_html=True)
            with col_y:
                st.markdown("**Top SHAP Contributors:**")
                for f in det["top_features"][:4]:
                    st.text(f"• {f['feature']}: {f['shap_value']:+.4f} (raw={f['feature_value']})")

            st.json(alert)
