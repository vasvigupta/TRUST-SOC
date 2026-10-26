# TRUST-SOC Alert Prioritisation Matrix Report

## 1. Operational 3x3 Matrix Breakdown

| Verification Decision | Detection $p_d$ HIGH (>=0.80) | Detection $p_d$ MEDIUM (0.50-0.80) | Detection $p_d$ LOW (<0.50) | Operational Triage Action |
|:---|:---:|:---:|:---:|:---|
| **CONFIRM** | **4,566** (4566 attacks / 0 FAs) | **7** | **0** | **Auto-Escalate** / High Priority Queue |
| **REDUCE** | **7,539** (7539 attacks / 0 FAs) | **24** | **4** | **Suspicious Review** / Standard Queue |
| **REJECT** | **358** (296 attacks / 62 FAs) | **169** | **15** | **Dropped False Alarm** (Audit Logged) |

## 2. Confidence Band Distribution

- **HIGH Band ($C \ge 0.80$):** 11,000 alerts (86.7%) — Auto-escalated for immediate SOC response.
- **MEDIUM Band ($0.50 \le C < 0.80$):** 1,492 alerts (11.8%) — Queued for senior analyst investigation.
- **LOW Band ($C < 0.50$):** 190 alerts (1.5%) — Suppressed / Logged without analyst interruption.

## 3. Operational Impact

- High-confidence alerts are auto-escalated with verifiable evidence.
- False alarms flagged by independent verification are reclassified as REJECT and suppressed, dramatically reducing alert fatigue.