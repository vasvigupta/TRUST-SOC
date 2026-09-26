"""
Verification Agent — STUB / Extension Point
=============================================
This is a PLACEHOLDER for the future Verification Agent.

Current prototype status:
  Stage 1–7 (Detection Agent) are COMPLETE.
  The Verification Agent is a PLANNED NEXT-STAGE COMPONENT.

Do NOT fake verification results.
All verify() calls explicitly return NOT_IMPLEMENTED.

Future implementation will add:
  - Rule / Context Corroboration
  - Statistical Anomaly Detection (Isolation Forest)
  - Behavioural Baseline
  - Explanation Consistency Check
  - Confidence Fusion Engine (CONFIRM / REDUCE / REJECT)
"""

import logging

log = logging.getLogger("TRUST-SOC.verification")


class VerificationResult:
    """Placeholder result object returned by the Verification Agent."""

    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

    def __init__(self):
        self.verdict              = self.NOT_IMPLEMENTED
        self.verification_confidence = None
        self.corroboration        = None
        self.explanation_note     = (
            "Verification Agent is not yet implemented. "
            "This is a planned Stage 2 component. "
            "Detection Agent output stands as-is."
        )

    def to_dict(self) -> dict:
        return {
            "verdict":                 self.verdict,
            "verification_confidence": self.verification_confidence,
            "corroboration":           self.corroboration,
            "explanation_note":        self.explanation_note,
        }

    def __repr__(self):
        return f"VerificationResult(verdict={self.verdict})"


class VerificationAgent:
    """
    Verification Agent (NOT YET IMPLEMENTED).

    Interface contract for the future implementation:

        agent = VerificationAgent()
        result = agent.verify(alert)
        # result.verdict in {"CONFIRM", "REDUCE", "REJECT"}

    Current behaviour: always returns NOT_IMPLEMENTED.
    """

    def __init__(self):
        log.debug("VerificationAgent initialised (stub).")

    def verify(self, alert: dict) -> VerificationResult:
        """
        Verify a Detection Agent alert.

        Parameters
        ----------
        alert : dict
            Alert object produced by the log replay / detection pipeline.

        Returns
        -------
        VerificationResult
            Stub result — NOT_IMPLEMENTED.
        """
        log.debug(
            f"VerificationAgent.verify() called for alert "
            f"{alert.get('alert_id', '?')} — returning NOT_IMPLEMENTED stub."
        )
        return VerificationResult()

    # ── Future methods (stubs) ────────────────────────────────────

    def _rule_corroboration(self, alert):
        """[FUTURE] Rule-based context corroboration."""
        raise NotImplementedError

    def _statistical_anomaly(self, alert):
        """[FUTURE] Isolation Forest anomaly check."""
        raise NotImplementedError

    def _behavioural_baseline(self, alert):
        """[FUTURE] Behavioural baseline deviation check."""
        raise NotImplementedError

    def _explanation_consistency(self, alert):
        """[FUTURE] SHAP explanation consistency check."""
        raise NotImplementedError

    def _confidence_fusion(self, scores):
        """[FUTURE] Fuse sub-scores → final CONFIRM/REDUCE/REJECT."""
        raise NotImplementedError
