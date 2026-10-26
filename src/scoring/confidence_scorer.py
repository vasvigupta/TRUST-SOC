"""
TRUST-SOC Confidence Scoring Engine (Milestone 3 — Stage 3.1 & 3.2)
==================================================================
Computes the composite confidence score C combining Detection Agent probability (p_d),
Verification Agent agreement score (p_v), and Rule/Context corroboration (r_corr).

Formula (Section 4.3):
  C = alpha * p_d + beta * p_v + gamma * r_corr,   where alpha + beta + gamma = 1

Confidence Bands:
  HIGH   : C >= 0.80   (Auto-escalated on dashboard)
  MEDIUM : 0.50 <= C < 0.80 (Queued for analyst review)
  LOW    : C < 0.50    (Logged only, not escalated)

Alert Prioritisation Matrix (Stage 3.2):
  Maps 3x3 interaction between p_d (High/Med/Low) and Verification Decision (CONFIRM/REDUCE/REJECT)
  to operational actions.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from src.config.config import (
    CONFIDENCE_WEIGHTS,
    BAND_HIGH_THRESHOLD,
    BAND_MEDIUM_THRESHOLD,
)


class ConfidenceScoringEngine:
    """Computes composite confidence scores, assigns triage bands, and operational actions."""

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        band_high: float = BAND_HIGH_THRESHOLD,
        band_medium: float = BAND_MEDIUM_THRESHOLD,
    ):
        self.weights = weights or CONFIDENCE_WEIGHTS
        self.alpha = float(self.weights.get("alpha", 0.40))
        self.beta = float(self.weights.get("beta", 0.40))
        self.gamma = float(self.weights.get("gamma", 0.20))

        # Validate weight sum within floating-point tolerance
        total_w = self.alpha + self.beta + self.gamma
        if abs(total_w - 1.0) > 1e-4:
            raise ValueError(
                f"Confidence weights must sum to 1.0 (got alpha={self.alpha}, "
                f"beta={self.beta}, gamma={self.gamma}, sum={total_w})"
            )

        self.band_high = float(band_high)
        self.band_medium = float(band_medium)

    def compute_confidence(
        self,
        p_d: float,
        p_v: float,
        r_corr: float,
        verification_decision: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Computes composite confidence score C and operational triage band.

        Args:
            p_d: Detection Agent probability for predicted class in [0, 1].
            p_v: Verification Agent agreement score in [0, 1].
            r_corr: Rule / context corroboration signal score in [0, 1].
            verification_decision: Decision from Verification Agent ("CONFIRM", "REDUCE", "REJECT").

        Returns:
            Dictionary matching the canonical scoring schema.
        """
        # Clamp inputs to [0, 1]
        p_d_clamped = max(0.0, min(1.0, float(p_d)))
        p_v_clamped = max(0.0, min(1.0, float(p_v)))
        r_corr_clamped = max(0.0, min(1.0, float(r_corr)))

        # Composite confidence formula
        C = self.alpha * p_d_clamped + self.beta * p_v_clamped + self.gamma * r_corr_clamped
        C = max(0.0, min(1.0, float(C)))

        # Assign confidence band
        if C >= self.band_high:
            band = "HIGH"
        elif C >= self.band_medium:
            band = "MEDIUM"
        else:
            band = "LOW"

        # Prioritisation Matrix (Stage 3.2):
        # 3x3 interaction between p_d level and Verification decision
        p_d_level = "HIGH" if p_d_clamped >= 0.80 else ("MEDIUM" if p_d_clamped >= 0.50 else "LOW")
        decision = verification_decision or "CONFIRM"

        if decision == "REJECT":
            # REJECT reclassifies as verified false positive; suppresses auto-escalation
            matrix_action = "FALSE_POSITIVE_LOGGED"
            action = "FALSE_POSITIVE_LOG"
        elif decision == "CONFIRM":
            if p_d_level == "HIGH":
                matrix_action = "URGENT_AUTO_ESCALATE"
                action = "AUTO_ESCALATE"
            elif p_d_level == "MEDIUM":
                matrix_action = "HIGH_PRIORITY_REVIEW"
                action = "ANALYST_QUEUE"
            else:
                matrix_action = "STANDARD_REVIEW"
                action = "ANALYST_QUEUE"
        elif decision == "REDUCE":
            if p_d_level == "HIGH":
                matrix_action = "MEDIUM_PRIORITY_REVIEW"
                action = "ANALYST_QUEUE"
            else:
                matrix_action = "STANDARD_REVIEW"
                action = "ANALYST_QUEUE" if C >= self.band_medium else "LOG_ONLY"
        else:
            # Default fallback for Benign / unverified
            matrix_action = "LOG_ONLY"
            action = "LOG_ONLY"

        return {
            "composite": round(C, 4),
            "band": band,
            "components": {
                "p_d": round(p_d_clamped, 4),
                "p_v": round(p_v_clamped, 4),
                "r_corr": round(r_corr_clamped, 4),
                "alpha": round(self.alpha, 4),
                "beta": round(self.beta, 4),
                "gamma": round(self.gamma, 4),
            },
            "action": action,
            "matrix_action": matrix_action,
        }

    def score_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates confidence score for a canonical alert dictionary, updates alert['scoring'],
        and appends an entry to alert['audit_trail'].
        """
        det = alert.get("detection", {})
        ver = alert.get("verification", {})

        p_d = float(det.get("probability", 0.0))
        p_v = float(ver.get("p_v", 0.0))

        signals = ver.get("signals", {})
        rule_sig = signals.get("rule", {})
        r_corr = float(rule_sig.get("score", 0.0))
        decision = str(ver.get("decision", "CONFIRM"))

        scoring_block = self.compute_confidence(
            p_d=p_d,
            p_v=p_v,
            r_corr=r_corr,
            verification_decision=decision,
        )

        alert["scoring"] = scoring_block

        now_iso = datetime.now(timezone.utc).isoformat()
        if "audit_trail" not in alert or not isinstance(alert["audit_trail"], list):
            alert["audit_trail"] = []

        alert["audit_trail"].append({
            "ts": now_iso,
            "stage": "scoring",
            "event": f"Confidence scored: C={scoring_block['composite']:.4f} ({scoring_block['band']}) -> {scoring_block['action']}",
        })

        return scoring_block
