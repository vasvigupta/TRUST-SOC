"""
Verification Agent (Stage 2.6)
==============================
The scientific core of TRUST-SOC.
Acts as an independent second line of defense against false alarms.
Evaluates 4 genuinely independent signals (r, s, b, e) and applies the
formal Decision Table to reach CONFIRM, REDUCE, or REJECT.

Strictly adheres to Section 4.2 and Section 11 specifications.
Rules:
1. Every signal returns float in [0, 1] (1 = corroborates attack, 0 = contradicts).
2. Every signal returns boolean strongly_contradictory (score < 0.20) + details dict.
3. No signal may inspect ground_truth.
4. Signals r, s, b form their opinion independently of Detection Agent probability p_d.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
import numpy as np
import joblib

from src.config.config import (
    VERIFICATION_WEIGHTS,
    P_V_CONFIRM_THRESHOLD,
    P_V_REDUCE_THRESHOLD,
    STRONG_CONTRADICTION_THRESHOLD,
    SCALER_PATH,
    IMPUTER_PATH,
    FEATURE_NAMES_PATH,
)
from src.verification.decision import compute_verification_decision
from src.verification.rule_signal import RuleContextVerifier
from src.verification.statistical_signal import StatisticalVerifier
from src.verification.behavioural_signal import BehaviouralVerifier
from src.verification.explanation_signal import ExplanationVerifier

log = logging.getLogger("TRUST-SOC.verification")


class VerificationAgent:
    """
    Independent Verification Engine combining 4 corroborating signals:
      - (a) Rule / Context Corroboration (r)
      - (b) Statistical Corroboration via Isolation Forest (s)
      - (c) Behavioural Baseline Check with Causal Window (b)
      - (d) Explanation Consistency Check via SHAP Semantic Alignment (e)
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        confirm_thresh: float = P_V_CONFIRM_THRESHOLD,
        reduce_thresh: float = P_V_REDUCE_THRESHOLD,
        strong_contra_thresh: float = STRONG_CONTRADICTION_THRESHOLD,
    ):
        self.weights = weights or VERIFICATION_WEIGHTS
        self.confirm_thresh = confirm_thresh
        self.reduce_thresh = reduce_thresh
        self.strong_contra_thresh = strong_contra_thresh

        log.info(
            f"Initializing VerificationAgent (confirm={self.confirm_thresh}, "
            f"reduce={self.reduce_thresh}, contra={self.strong_contra_thresh}, "
            f"weights={self.weights})"
        )

        self.rule_verifier = RuleContextVerifier(strong_contra_thresh=self.strong_contra_thresh)
        self.statistical_verifier = StatisticalVerifier(strong_contra_thresh=self.strong_contra_thresh)
        self.behavioural_verifier = BehaviouralVerifier(strong_contra_thresh=self.strong_contra_thresh)
        self.explanation_verifier = ExplanationVerifier(strong_contra_thresh=self.strong_contra_thresh)

        # Lazy loaded preprocessors for scaled vector creation if needed
        self._scaler = None
        self._imputer = None
        self._feature_names = None

    def _ensure_preprocessors(self):
        if self._scaler is None and SCALER_PATH.exists():
            self._scaler = joblib.load(SCALER_PATH)
            self._imputer = joblib.load(IMPUTER_PATH)
            self._feature_names = joblib.load(FEATURE_NAMES_PATH)

    def verify_flow(
        self,
        predicted_class: str,
        flow_metadata: Dict[str, Any],
        flow_features: Dict[str, Any],
        scaled_vector: Optional[np.ndarray] = None,
        shap_features: Optional[Union[List[Dict[str, Any]], Dict[str, float]]] = None,
        update_behavioural_window: bool = True,
    ) -> Dict[str, Any]:
        """
        Runs independent verification on a single flow.

        Args:
            predicted_class: Detection Agent predicted class.
            flow_metadata: IP, port, protocol, timestamp metadata.
            flow_features: Dict of unscaled feature values.
            scaled_vector: 68-d scaled feature array for Isolation Forest.
            shap_features: Top-k SHAP attribution features.
            update_behavioural_window: Whether to causally update the behavioural window.

        Returns:
            Canonical verification dictionary.
        """
        # If predicted class is Benign, it is not an attack alert
        if predicted_class == "Benign":
            return {
                "decision": "CONFIRM_BENIGN",
                "p_v": 0.0,
                "signals": {
                    "rule": {"score": 0.0, "strongly_contradictory": False, "details": {"note": "Benign flow - no verification required"}},
                    "statistical": {"score": 0.0, "strongly_contradictory": False, "details": {"note": "Benign flow - no verification required"}},
                    "behavioural": {"score": 0.0, "strongly_contradictory": False, "details": {"note": "Benign flow - no verification required"}},
                    "explanation": {"score": 0.0, "strongly_contradictory": False, "details": {"note": "Benign flow - no verification required"}},
                },
                "rationale": "Detection Agent classified flow as Benign. Verification layer stands idle.",
            }

        # 1. Rule / context corroboration (r)
        r_signal = self.rule_verifier.verify_flow(
            predicted_class=predicted_class,
            flow_metadata=flow_metadata,
            flow_features=flow_features,
        )

        # 2. Statistical corroboration (s)
        if scaled_vector is None:
            self._ensure_preprocessors()
            if self._scaler is not None and self._feature_names is not None:
                raw_vec = np.array([flow_features.get(f, 0.0) for f in self._feature_names], dtype=np.float32).reshape(1, -1)
                raw_clean = np.where(np.isinf(raw_vec), np.nan, raw_vec)
                imp_vec = self._imputer.transform(raw_clean)
                scaled_vector = self._scaler.transform(imp_vec)[0]
            else:
                scaled_vector = np.zeros(68, dtype=np.float32)

        s_signal = self.statistical_verifier.verify_flow(scaled_vector)

        # 3. Behavioural baseline check (b)
        b_signal = self.behavioural_verifier.verify_flow(
            flow_metadata=flow_metadata,
            flow_features=flow_features,
            update_window=update_behavioural_window,
        )

        # 4. Explanation consistency check (e)
        e_signal = self.explanation_verifier.verify_explanation(
            predicted_class=predicted_class,
            shap_features=shap_features,
            scaled_vector=scaled_vector,
            feature_names=self._feature_names,
        )

        # 5. Composite decision table evaluation
        decision_dict = compute_verification_decision(
            r_signal=r_signal,
            s_signal=s_signal,
            b_signal=b_signal,
            e_signal=e_signal,
            weights=self.weights,
            confirm_thresh=self.confirm_thresh,
            reduce_thresh=self.reduce_thresh,
            strong_contra_thresh=self.strong_contra_thresh,
        )

        return decision_dict

    def verify(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes an alert through the full verification engine and updates it.
        Takes Section 5 Canonical Alert schema dictionary.
        """
        det = alert.get("detection", {})
        predicted_class = det.get("predicted_class", "Benign")
        flow = alert.get("flow", {})
        flow_metadata = flow.get("fields_available", {})
        flow_features = flow.get("features", {})
        shap_features = det.get("top_features", [])

        ver_block = self.verify_flow(
            predicted_class=predicted_class,
            flow_metadata=flow_metadata,
            flow_features=flow_features,
            shap_features=shap_features,
            update_behavioural_window=True,
        )

        alert["verification"] = ver_block
        return ver_block


def run_verification():
    """CLI runner for Milestone 2 Verification Agent evaluation."""
    from src.verification.evaluate_verification import run_test_evaluation
    log.info("Executing Milestone 2 Verification Agent Evaluation...")
    run_test_evaluation()

