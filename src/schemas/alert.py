"""
TRUST-SOC Canonical Alert Schema (Section 5)
=============================================
Defines the standard dictionary/dataclass schema flowing through the pipeline.
Grows milestone by milestone.
Includes validate_alert() with zero external library dependencies.

CRITICAL RULE:
`ground_truth` is stored for evaluation only. No operational agent
(Detection, Verification, Scoring, Report) may read it to make a decision.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


SCHEMA_VERSION = "1.0"


def create_empty_alert(
    source_file: str,
    row_index: int,
    fields_available: Dict[str, Any],
    features: Dict[str, float],
    ground_truth: Optional[Dict[str, Any]] = None,
    alert_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Creates a new Alert dictionary adhering to the Section 5 Canonical Alert Schema.
    Initializes stages beyond detection to their appropriate uncompleted states.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    uid = alert_id or f"alert-{uuid.uuid4().hex[:8]}:{row_index}"

    alert = {
        "schema_version": SCHEMA_VERSION,
        "alert_id": uid,
        "ingested_at": now_iso,
        "flow": {
            "source_file": source_file,
            "row_index": row_index,
            "fields_available": fields_available,
            "features": features,
        },
        "detection": {
            "model": "none",
            "predicted_class": "Benign",
            "probability": 0.0,
            "class_probabilities": {},
            "top_features": [],
            "is_alert": False,
        },
        "verification": {
            "decision": "NOT_IMPLEMENTED",
            "p_v": 0.0,
            "signals": {
                "rule": {"score": 0.0, "strongly_contradictory": False, "details": {}},
                "statistical": {"score": 0.0, "strongly_contradictory": False, "details": {}},
                "behavioural": {"score": 0.0, "strongly_contradictory": False, "details": {}},
                "explanation": {"score": 0.0, "strongly_contradictory": False, "details": {}},
            },
            "rationale": "Verification Agent not yet executed.",
        },
        "scoring": {
            "composite": 0.0,
            "band": "LOW",
            "weights": {"alpha": 0.4, "beta": 0.4, "gamma": 0.2},
            "r_corr": 0.0,
        },
        "mitre": [],
        "audit_trail": [
            {"ts": now_iso, "stage": "ingestion", "event": "Flow record ingested and schema initialized"}
        ],
    }

    if ground_truth is not None:
        alert["ground_truth"] = ground_truth

    return alert


def validate_alert(alert: Dict[str, Any]) -> bool:
    """
    Hand-written schema validator (no external dependencies).
    Raises ValueError with specific explanation if schema contract is violated.
    """
    required_top_keys = [
        "schema_version",
        "alert_id",
        "ingested_at",
        "flow",
        "detection",
        "verification",
        "scoring",
        "audit_trail",
    ]
    for k in required_top_keys:
        if k not in alert:
            raise ValueError(f"Schema violation: missing top-level key '{k}'")

    if alert["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"Schema version mismatch: expected {SCHEMA_VERSION}, got {alert['schema_version']}")

    # Validate flow block
    flow = alert["flow"]
    for fk in ["source_file", "row_index", "fields_available", "features"]:
        if fk not in flow:
            raise ValueError(f"Flow block missing required key '{fk}'")

    # Validate detection block
    det = alert["detection"]
    for dk in ["model", "predicted_class", "probability", "class_probabilities", "is_alert"]:
        if dk not in det:
            raise ValueError(f"Detection block missing required key '{dk}'")

    if not (0.0 <= det["probability"] <= 1.00001):
        raise ValueError(f"Detection probability out of bounds: {det['probability']}")

    # Validate verification block
    ver = alert["verification"]
    for vk in ["decision", "p_v", "signals", "rationale"]:
        if vk not in ver:
            raise ValueError(f"Verification block missing required key '{vk}'")

    # Validate audit trail
    if not isinstance(alert["audit_trail"], list) or len(alert["audit_trail"]) == 0:
        raise ValueError("Audit trail must be a non-empty list of event entries")

    return True
