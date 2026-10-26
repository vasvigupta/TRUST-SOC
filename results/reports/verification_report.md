# TRUST-SOC Verification Agent — Test Set Evaluation Report

## Executive Summary

- **Primary Success Metric (FPR Reduction):**
  - Baseline Detection Agent FPR: **1.3721%** (247 false alarms)
  - Post-Verification Lenient FPR: **0.0167%** (3 surviving false alarms)
  - **Relative FPR Reduction:** **98.79%**
  - **Absolute FPR Reduction:** **1.3555 percentage points**
  - Post-Verification Strict FPR: **0.0%** (0 surviving false alarms, **100.0%** reduction)
- **Recall Cost:** **2.3942%** (298 out of 12435 true attacks rejected)
- **Cohen's Kappa Agreement:** **0.608** (high agreement with ground truth)

## Per-Class Breakdown

| Predicted Attack Class | Initial False Alarms | Rejected False Alarms | FA Reduction (%) | Attack Alerts | Rejected Attacks | Recall Retention (%) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Botnet** | 217 | 217 | **100.0%** | 293 | 288 | 1.71% |
| **Brute Force** | 9 | 9 | **100.0%** | 2073 | 10 | 99.52% |
| **DoS/DDoS** | 6 | 3 | **50.0%** | 5999 | 0 | 100.0% |
| **Port Scan** | 0 | 0 | **100.0%** | 3748 | 0 | 100.0% |
| **Web Attack** | 15 | 15 | **100.0%** | 322 | 0 | 100.0% |

## Verification Decisions Breakdown

- **CONFIRM:** 4,573 alerts
- **REDUCE:** 7,567 alerts
- **REJECT:** 542 alerts (verified false positives dropped)

## Verification Agent Parameters

- Weights: `{"r": 0.3, "s": 0.25, "b": 0.25, "e": 0.2}`
- Confirm Threshold ($p_v$): `0.7`
- Reduce Threshold ($p_v$): `0.4`
- Strong Contradiction Threshold: `0.2`