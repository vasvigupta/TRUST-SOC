"""
FastAPI Route — /api/detect
===========================
POST /api/detect
  Body: { "features": { ... }, "metadata": { ... } }
  Runs full TRUST-SOC pipeline:
    1. Feature scaling & preprocessing
    2. Detection Agent classification (Random Forest / XGBoost)
    3. SHAP TreeExplainer local attribution
    4. Verification Agent 4-signal corroboration (r, s, b, e) -> p_v -> CONFIRM / REDUCE / REJECT
    5. Confidence Scoring Engine -> Composite score C & Band (HIGH / MEDIUM / LOW)
    6. Persists to SQLite alert store & generates ReportLab PDF evidence report
"""

import datetime
from datetime import timezone
import uuid
import json
from pathlib import Path
from typing import Dict, Any

from fastapi import APIRouter, HTTPException

from src.api.schemas import DetectRequest, DetectResponse
from src.config.config import SAMPLE_DIR
from src.ingestion.log_replay import LogReplaySimulator
from src.reporting.report_generator import ReportGenerator

router = APIRouter(prefix="/api/detect", tags=["Detection"])

# Lazy singleton simulator
_simulator = None

def _get_simulator():
    global _simulator
    if _simulator is None:
        _simulator = LogReplaySimulator(enable_shap=True)
    return _simulator


@router.post("", response_model=DetectResponse, summary="Process single network flow through the full TRUST-SOC pipeline")
def detect_single_flow(req: DetectRequest):
    """
    Submits a network-flow feature dict and runs the end-to-end pipeline:
    DETECT -> VERIFY -> EXPLAIN -> PRIORITIZE.
    """
    try:
        sim = _get_simulator()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model loading error: {e}")

    now_iso = datetime.datetime.now(timezone.utc).isoformat()
    metadata = req.metadata or {
        "Source IP": "192.168.10.50",
        "Destination IP": "172.16.0.1",
        "Source Port": 49152,
        "Destination Port": 80,
        "Protocol": 6,
        "Timestamp": now_iso,
    }

    # Populate full feature set with defaults for missing dimensions
    features = {f: float(req.features.get(f, 0.0)) for f in sim.feature_names}

    raw_msg = {
        "key": f"single:{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso,
        "source_file": "single_flow_api",
        "row_index": 0,
        "fields_available": metadata,
        "features": features,
        "ground_truth": {
            "original_label": "Unknown",
            "project_class": "Unknown",
            "is_attack": True,
        },
    }

    try:
        alert = sim.process_record(raw_msg)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Flow processing failed: {e}")

    # Generate PDF and JSON reports
    try:
        ReportGenerator().generate_both_reports(alert)
    except Exception as e:
        pass  # Non-fatal if PDF generation encounters minor issue

    alert_id = alert["alert_id"]
    det = alert.get("detection", {})
    ver = alert.get("verification", {})
    sc = alert.get("scoring", {})

    return DetectResponse(
        alert_id=alert_id,
        timestamp=alert.get("timestamp", now_iso),
        prediction=det.get("predicted_class", "Benign"),
        probability=float(det.get("probability", 0.0)),
        verification_decision=ver.get("decision", "CONFIRM"),
        verification_pv=float(ver.get("p_v", 0.0)),
        composite_confidence=float(sc.get("composite", 0.0)),
        confidence_band=sc.get("band", "LOW"),
        rationale=ver.get("rationale", ""),
        signals=ver.get("signals", {}),
        top_features=det.get("top_features", []),
        class_probabilities=det.get("class_probabilities", {}),
        pdf_report_url=f"/api/alerts/{alert_id}/report/pdf",
        json_report_url=f"/api/alerts/{alert_id}/report/json",
    )


@router.get("/examples", summary="Get pre-configured example flow records for threat classes")
def get_examples():
    """Returns sample feature payloads for demonstration."""
    examples_file = SAMPLE_DIR / "neutral_example_flows.json"
    if not examples_file.exists():
        examples_file = SAMPLE_DIR / "example_flows.json"
    if examples_file.exists():
        try:
            return json.loads(examples_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Standard fallback test flows
    return {
        "DoS/DDoS Attack Sample": {
            "Destination Port": 80.0,
            "Flow Duration": 182345.0,
            "Total Fwd Packets": 24.0,
            "Total Backward Packets": 1.0,
            "Total Length of Fwd Packets": 1420.0,
            "Flow Packets/s": 137.1,
            "Flow Bytes/s": 7787.4,
            "Packet Length Mean": 59.2,
            "Packet Length Std": 12.4,
        },
        "Port Scan Probe Sample": {
            "Destination Port": 445.0,
            "Flow Duration": 42.0,
            "Total Fwd Packets": 2.0,
            "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": 0.0,
            "Flow Packets/s": 47619.0,
            "Flow Bytes/s": 0.0,
            "Packet Length Mean": 0.0,
            "Packet Length Std": 0.0,
        },
        "Brute Force Sample": {
            "Destination Port": 22.0,
            "Flow Duration": 521400.0,
            "Total Fwd Packets": 18.0,
            "Total Backward Packets": 12.0,
            "Total Length of Fwd Packets": 840.0,
            "Flow Packets/s": 57.5,
            "Flow Bytes/s": 2840.0,
            "Packet Length Mean": 48.0,
            "Packet Length Std": 22.0,
        },
        "Benign Normal Traffic": {
            "Destination Port": 443.0,
            "Flow Duration": 1250000.0,
            "Total Fwd Packets": 12.0,
            "Total Backward Packets": 14.0,
            "Total Length of Fwd Packets": 640.0,
            "Flow Packets/s": 20.8,
            "Flow Bytes/s": 3200.0,
            "Packet Length Mean": 123.0,
            "Packet Length Std": 45.0,
        },
    }
