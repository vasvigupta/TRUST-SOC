"""
Signal (d): Explanation Consistency Check (e)
==============================================
Evaluates whether the Detection Agent's SHAP feature attributions semantically
align with the expected network domain feature families for the predicted attack class.

Strictly adheres to Section 4.2(d) and Section 11 (Milestone 2) specifications.
Does NOT inspect ground_truth or Detection Agent probability p_d.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import numpy as np

from src.config.config import (
    RULES_PATH,
    STRONG_CONTRADICTION_THRESHOLD,
)


class ExplanationVerifier:
    """Verifies semantic alignment between SHAP top features and attack domain physics."""

    def __init__(
        self,
        rules_path: Path = RULES_PATH,
        strong_contra_thresh: float = STRONG_CONTRADICTION_THRESHOLD,
    ):
        self.strong_contra_thresh = strong_contra_thresh
        with open(rules_path, "r", encoding="utf-8") as f:
            self.rules_config = json.load(f)

        self.class_rules = self.rules_config.get("classes", {})

    def verify_explanation(
        self,
        predicted_class: str,
        shap_features: Optional[Union[List[Dict[str, Any]], Dict[str, float]]] = None,
        scaled_vector: Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Computes explanation consistency score e in [0, 1].

        Args:
            predicted_class: The attack class predicted by the Detection Agent.
            shap_features: Top-k SHAP attribution features. Can be a list of dicts
                           [{"feature": name, "shap_value": val}] or a dict {name: val}.
            scaled_vector: Optional 68-d feature array used as fallback to derive
                           active features when SHAP is not pre-computed.
            feature_names: Feature names corresponding to scaled_vector.

        Returns:
            Dict conforming to common signal contract:
            {"score": float, "strongly_contradictory": bool, "details": dict}
        """
        if predicted_class not in self.class_rules:
            return {
                "score": 0.5,
                "strongly_contradictory": False,
                "details": {"reason": f"Class '{predicted_class}' has no explanation profile."},
            }

        rule_def = self.class_rules[predicted_class]
        expected_families = rule_def.get("expected_feature_families", [])

        # Extract features and attribution weights
        items: List[tuple] = []
        if isinstance(shap_features, dict):
            for k, v in shap_features.items():
                items.append((str(k), abs(float(v))))
        elif isinstance(shap_features, list) and len(shap_features) > 0:
            for item in shap_features:
                if isinstance(item, dict):
                    name = item.get("feature") or item.get("name") or ""
                    val = item.get("shap_value") or item.get("value") or item.get("importance") or 0.0
                    items.append((str(name), abs(float(val))))
        elif scaled_vector is not None and feature_names is not None:
            # High-speed vectorized fallback: active features with highest absolute deviation
            vec = np.asarray(scaled_vector).ravel()
            if len(vec) == len(feature_names):
                abs_vec = np.abs(vec)
                top_k_idx = np.argsort(abs_vec)[-10:][::-1]
                for idx in top_k_idx:
                    items.append((feature_names[idx], float(abs_vec[idx])))

        if not items:
            return {
                "score": 0.5,
                "strongly_contradictory": False,
                "details": {
                    "expected_families": expected_families,
                    "explanation": "No feature attribution provided; assigned neutral score 0.50.",
                },
            }

        total_mass = 0.0
        consistent_mass = 0.0
        consistent_features = []
        inconsistent_features = []

        for feat_name, mass in items:
            total_mass += mass
            is_consistent = False
            feat_lower = feat_name.lower()
            for family in expected_families:
                if family.lower() in feat_lower:
                    is_consistent = True
                    break

            if is_consistent:
                consistent_mass += mass
                consistent_features.append(feat_name)
            else:
                inconsistent_features.append(feat_name)

        if total_mass <= 0:
            consistency_ratio = 0.5
        else:
            consistency_ratio = consistent_mass / total_mass

        score = max(0.0, min(1.0, float(consistency_ratio)))

        interpretation = (
            f"Explanation ({score:.1%}) strongly aligns with domain expectations for {predicted_class}"
            if score >= 0.50
            else f"Explanation ({score:.1%}) deviates from expected domain features for {predicted_class} (possible artifact)"
        )

        details = {
            "expected_families": expected_families,
            "consistent_features": consistent_features[:5],
            "inconsistent_features": inconsistent_features[:5],
            "consistency_ratio": round(consistency_ratio, 4),
            "interpretation": interpretation,
        }

        return {
            "score": round(score, 4),
            "strongly_contradictory": score < self.strong_contra_thresh,
            "details": details,
        }
