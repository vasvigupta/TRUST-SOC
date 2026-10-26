"""
TRUST-SOC Verification Decision Engine
======================================
Combines 4 independent verification signals (r, s, b, e) into an agreement score p_v
and computes the verification decision: CONFIRM, REDUCE, or REJECT.

Strictly adheres to Section 4.2 and Section 11 (Milestone 2) specifications.
"""

from typing import Dict, Any, Optional
from src.config.config import (
    VERIFICATION_WEIGHTS,
    P_V_CONFIRM_THRESHOLD,
    P_V_REDUCE_THRESHOLD,
    STRONG_CONTRADICTION_THRESHOLD,
)


def compute_verification_decision(
    r_signal: Dict[str, Any],
    s_signal: Dict[str, Any],
    b_signal: Dict[str, Any],
    e_signal: Dict[str, Any],
    weights: Optional[Dict[str, float]] = None,
    confirm_thresh: float = P_V_CONFIRM_THRESHOLD,
    reduce_thresh: float = P_V_REDUCE_THRESHOLD,
    strong_contra_thresh: float = STRONG_CONTRADICTION_THRESHOLD,
) -> Dict[str, Any]:
    """
    Computes the agreement score p_v and verification decision from 4 independent signals.

    Args:
        r_signal: Rule/context corroboration signal dict {"score": float, "strongly_contradictory": bool, "details": dict}
        s_signal: Statistical corroboration signal dict {"score": float, "strongly_contradictory": bool, "details": dict}
        b_signal: Behavioural baseline signal dict {"score": float, "strongly_contradictory": bool, "details": dict}
        e_signal: Explanation consistency signal dict {"score": float, "strongly_contradictory": bool, "details": dict}
        weights: Dict with keys 'r', 's', 'b', 'e'
        confirm_thresh: Minimum p_v for CONFIRM (default 0.70)
        reduce_thresh: Minimum p_v for REDUCE (default 0.40)
        strong_contra_thresh: Threshold below which a signal is strongly contradictory (default 0.20)

    Returns:
        Canonical verification block matching Section 5 schema.
    """
    if weights is None:
        weights = VERIFICATION_WEIGHTS

    w_r = weights.get("r", 0.25)
    w_s = weights.get("s", 0.25)
    w_b = weights.get("b", 0.25)
    w_e = weights.get("e", 0.25)
    total_w = w_r + w_s + w_b + w_e
    if total_w <= 0:
        total_w = 1.0

    # Extract clamped scores in [0, 1]
    r_val = max(0.0, min(1.0, float(r_signal.get("score", 0.0))))
    s_val = max(0.0, min(1.0, float(s_signal.get("score", 0.0))))
    b_val = max(0.0, min(1.0, float(b_signal.get("score", 0.0))))
    e_val = max(0.0, min(1.0, float(e_signal.get("score", 0.0))))

    # Compute agreement score p_v
    p_v = (w_r * r_val + w_s * s_val + w_b * b_val + w_e * e_val) / total_w
    p_v = max(0.0, min(1.0, float(p_v)))

    # Evaluate strong contradictions (< threshold or flag set)
    signals_dict = {
        "rule": {
            "name": "Rule/Context",
            "score": r_val,
            "strongly_contradictory": bool(r_signal.get("strongly_contradictory", r_val < strong_contra_thresh)),
            "details": r_signal.get("details", {}),
        },
        "statistical": {
            "name": "Statistical Anomaly (IForest)",
            "score": s_val,
            "strongly_contradictory": bool(s_signal.get("strongly_contradictory", s_val < strong_contra_thresh)),
            "details": s_signal.get("details", {}),
        },
        "behavioural": {
            "name": "Behavioural Baseline",
            "score": b_val,
            "strongly_contradictory": bool(b_signal.get("strongly_contradictory", b_val < strong_contra_thresh)),
            "details": b_signal.get("details", {}),
        },
        "explanation": {
            "name": "Explanation Consistency",
            "score": e_val,
            "strongly_contradictory": bool(e_signal.get("strongly_contradictory", e_val < strong_contra_thresh)),
            "details": e_signal.get("details", {}),
        },
    }

    contradictory_keys = [k for k, sig in signals_dict.items() if sig["strongly_contradictory"]]
    num_contra = len(contradictory_keys)

    # Decision Table:
    # REJECT: p_v < reduce_thresh (0.40) OR >= 2 signals strongly contradictory
    # CONFIRM: p_v >= confirm_thresh (0.70) AND 0 signals strongly contradictory
    # REDUCE: 0.40 <= p_v < 0.70 OR signals partially disagree (e.g. p_v >= 0.70 but 1 contradictory)
    if p_v < reduce_thresh or num_contra >= 2:
        decision = "REJECT"
    elif p_v >= confirm_thresh and num_contra == 0:
        decision = "CONFIRM"
    else:
        decision = "REUCE" if False else "REDUCE"

    # Deterministic Rationale Generation
    rationale = _build_rationale(
        decision=decision,
        p_v=p_v,
        signals=signals_dict,
        num_contra=num_contra,
        contradictory_keys=contradictory_keys,
        confirm_thresh=confirm_thresh,
        reduce_thresh=reduce_thresh,
    )

    return {
        "decision": decision,
        "p_v": round(p_v, 4),
        "signals": {
            "rule": {
                "score": round(r_val, 4),
                "strongly_contradictory": signals_dict["rule"]["strongly_contradictory"],
                "details": signals_dict["rule"]["details"],
            },
            "statistical": {
                "score": round(s_val, 4),
                "strongly_contradictory": signals_dict["statistical"]["strongly_contradictory"],
                "details": signals_dict["statistical"]["details"],
            },
            "behavioural": {
                "score": round(b_val, 4),
                "strongly_contradictory": signals_dict["behavioural"]["strongly_contradictory"],
                "details": signals_dict["behavioural"]["details"],
            },
            "explanation": {
                "score": round(e_val, 4),
                "strongly_contradictory": signals_dict["explanation"]["strongly_contradictory"],
                "details": signals_dict["explanation"]["details"],
            },
        },
        "rationale": rationale,
    }


def _build_rationale(
    decision: str,
    p_v: float,
    signals: Dict[str, Dict[str, Any]],
    num_contra: int,
    contradictory_keys: list,
    confirm_thresh: float,
    reduce_thresh: float,
) -> str:
    """Generates an honest, deterministic rationale detailing signal consensus and discordance."""
    r_s = signals["rule"]["score"]
    s_s = signals["statistical"]["score"]
    b_s = signals["behavioural"]["score"]
    e_s = signals["explanation"]["score"]

    agreeing = [sig["name"] for sig in signals.values() if sig["score"] >= 0.60]
    disagreeing = [sig["name"] for sig in signals.values() if sig["score"] < 0.40]

    parts = [f"Decision {decision} (agreement p_v={p_v:.3f})."]

    if decision == "CONFIRM":
        parts.append(
            f"Strong multi-signal consensus corroborates attack: "
            f"rule={r_s:.2f}, statistical={s_s:.2f}, behavioural={b_s:.2f}, explanation={e_s:.2f}. "
            f"No strongly contradictory signals detected."
        )
    elif decision == "REJECT":
        if num_contra >= 2:
            names = ", ".join(signals[k]["name"] for k in contradictory_keys)
            parts.append(
                f"Rejected due to {num_contra} strongly contradictory signals ({names}) "
                f"indicating benign traffic characteristics despite detection alert."
            )
        else:
            parts.append(
                f"Agreement score ({p_v:.3f}) fell below rejection threshold ({reduce_thresh:.2f}). "
                f"Independent signals do not corroborate the alert (rule={r_s:.2f}, statistical={s_s:.2f}, "
                f"behavioural={b_s:.2f}, explanation={e_s:.2f})."
            )
    else:  # REDUCE
        if num_contra == 1:
            contra_name = signals[contradictory_keys[0]]["name"]
            parts.append(
                f"Partial signal disagreement: {contra_name} contradicts attack verdict, "
                f"while other signals show moderate-to-high corroboration. "
                f"Downgraded to REDUCE for analyst review."
            )
        else:
            parts.append(
                f"Moderate corroboration (p_v={p_v:.3f} in [{reduce_thresh:.2f}, {confirm_thresh:.2f})). "
                f"Signals exhibit mixed confidence (rule={r_s:.2f}, statistical={s_s:.2f}, "
                f"behavioural={b_s:.2f}, explanation={e_s:.2f}). Retained at reduced weight."
            )

    return " ".join(parts)
