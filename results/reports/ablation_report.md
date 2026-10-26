# TRUST-SOC Verification Agent — Validation Ablation Study

**Baseline Detection Agent FPR:** 1.239% (223 false alarms on benign flows)
**Validation Attack Alerts:** 12437 attacks

## 1. Ablation Summary Table

| Configuration | FA Rejected | FA Remaining (Lenient) | Lenient FPR | Rel FPR Red (%) | Attacks Retained | Recall Cost (%) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Signal (a) Alone [Rule]** | 167 | 56 | 0.311% | **74.9%** | 12436 | 0.01% |
| **Signal (b) Alone [Statistical]** | 221 | 2 | 0.011% | **99.1%** | 4101 | 66.97% |
| **Signal (c) Alone [Behavioural]** | 217 | 6 | 0.033% | **97.3%** | 11373 | 8.55% |
| **Signal (d) Alone [Explanation]** | 151 | 72 | 0.400% | **67.7%** | 11517 | 7.39% |
| **Leave-One-Out: Without (a) [s + b + e]** | 220 | 3 | 0.017% | **98.7%** | 11064 | 11.03% |
| **Leave-One-Out: Without (b) [r + b + e]** | 179 | 44 | 0.244% | **80.3%** | 12423 | 0.11% |
| **Leave-One-Out: Without (c) [r + s + e]** | 179 | 44 | 0.244% | **80.3%** | 11800 | 5.12% |
| **Leave-One-Out: Without (d) [r + s + b]** | 220 | 3 | 0.017% | **98.7%** | 11976 | 3.70% |
| **Full Mechanism (Fused 4 Signals)** | 220 | 3 | 0.017% | **98.7%** | 12149 | 2.31% |

## 2. Key Observations & Signal Roles

- **Signal (a) [Rule/Context]:** Provides essential grounding against obvious non-attack ports and whitelisted infrastructure.
- **Signal (b) [Statistical / Isolation Forest]:** Trained strictly on benign data, detects deviations from normal traffic without class bias.
- **Signal (c) [Behavioural Baseline]:** Flags host-level volume surges and historical traffic deviations via causal sliding windows.
- **Signal (d) [Explanation Consistency]:** Eliminates false alarms caused by non-attack feature artifacts.
- **Multi-Signal Consensus:** The fused 4-signal verification achieves superior false positive rejection while maintaining high attack recall.

## 3. Tuned Parameters (Selected on Validation Split)

- Weights: `{"r": 0.3, "s": 0.25, "b": 0.25, "e": 0.2}`
- Confirm Threshold ($p_v$): `0.7`
- Reduce Threshold ($p_v$): `0.4`
- Strong Contradiction Threshold: `0.2`