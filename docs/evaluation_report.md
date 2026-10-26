# TRUST-SOC: Consolidated Evaluation Report (Milestone 5)

> **Document Type**: Comprehensive Research & Evaluation Report  
> **System**: TRUST-SOC (Trust-Aware, Verification-Driven Detection Pipeline for Security Operations Centers)  
> **Date**: October 2026  
> **Canonical Results Data**: `results/final_summary.json`

---

## 1. Executive Summary & Primary Success Metric

The primary objective of **TRUST-SOC** is to mitigate alert fatigue in modern Security Operations Centers by introducing an **independent verification layer** that systematically filters false alarms while retaining true attacks.

### Primary Success Metric: False-Positive Rate (FPR) Reduction

$$\text{Relative FPR Reduction} = \frac{\text{FPR}_{\text{baseline}} - \text{FPR}_{\text{verified}}}{\text{FPR}_{\text{baseline}}} \times 100\%$$

$$\text{Absolute FPR Reduction} = \text{FPR}_{\text{baseline}} - \text{FPR}_{\text{verified}} \quad (\text{percentage points})$$

$$\text{Recall Cost} = \text{Recall}_{\text{baseline}} - \text{Recall}_{\text{verified}} \quad (\text{percentage points})$$

### Headline Quantitative Scorecard

| Evaluation Benchmark | Baseline FPR (Detection Agent Alone) | Post-Verification Lenient FPR | Post-Verification Strict FPR | Relative FPR Reduction (%) | Absolute FPR Reduction (pp) | Attack Recall Cost (%) | Inter-Agent Agreement ($\kappa$) |
|---|---|---|---|---|---|---|---|
| **CICIDS2017 (Primary Test Split)** | **1.3721%** (247 / 18,001 FPs) | **0.0167%** (3 / 18,001 FPs) | **0.0000%** (0 / 18,001 FPs) | **98.79%** | **1.3555 pp** | **2.39%** (Retained 97.60%) | **0.608** (Substantial) |
| **CSE-CIC-IDS2018 (Zero-Shot Cross-Dataset)** | **1.3889%** (25 / 1,800 FPs) | **0.0556%** (1 / 1,800 FPs) | **0.0000%** (0 / 1,800 FPs) | **96.00%** | **1.3333 pp** | **38.67%** (Domain Shift Impact) | **0.542** (Moderate) |

---

## 2. In-Domain Evaluation on CICIDS2017

### 2.1 Detection Agent Baseline Quality
- **Algorithm**: Balanced Random Forest (`n_estimators=100, max_depth=18`).
- **Test Set Size**: 30,448 flows (18,001 Benign, 12,447 Attacks).
- **Overall Accuracy**: **99.88%**
- **Weighted F1-Score**: **0.9988**
- **Macro F1-Score**: **0.9924**

#### Per-Class Performance on Held-Out Test Split

| Threat Class | Support | Precision | Recall | F1-Score | Baseline False Alarms Generated |
|---|---|---|---|---|---|
| **Benign** | 18,001 | 0.9998 | 0.9863 | 0.9930 | 247 on benign traffic (1.3721% FPR) |
| **DoS/DDoS** | 6,000 | 0.9980 | 0.9997 | 0.9988 | — |
| **Port Scan** | 3,750 | 0.9989 | 0.9992 | 0.9991 | — |
| **Brute Force** | 2,075 | 0.9976 | 0.9976 | 0.9976 | — |
| **Web Attack** | 327 | 0.9702 | 0.9969 | 0.9834 | — |
| **Botnet** | 295 | 0.9898 | 0.9831 | 0.9864 | — |

---

## 3. Independent Verification & Trust Mechanism

### 3.1 The 4-Signal Multi-Corroboration Architecture

The Verification Agent computes four independent signals, strictly enforcing causal and ground-truth isolation:
1. **Rule / Context Corroboration ($r$)**: Asset whitelist, destination port criticality, and MITRE technique signatures ($w_r = 0.30$).
2. **Statistical Corroboration ($s$)**: Isolation Forest anomaly check trained strictly on clean benign traffic ($w_s = 0.25$).
3. **Behavioural Baseline Corroboration ($b$)**: Rolling window ($W=50$) packet rate and byte volume $z$-score deviation against host profiles ($w_b = 0.25$).
4. **Explanation Consistency ($e$)**: Semantic alignment score measuring whether top SHAP attribution mass matches the predicted threat vector ($w_e = 0.20$).

Agreement score:
$$p_v = 0.30 r + 0.25 s + 0.25 b + 0.20 e$$

### 3.2 Formal Decision Logic
- **`CONFIRM`**: $p_v \ge 0.70$ and 0 contradictory signals $\to$ Retained at full strength; auto-escalated if composite score $C \ge 0.80$.
- **`REDUCE`**: $0.40 \le p_v < 0.70$ or 1 signal strongly contradicts $\to$ Down-weighted; queued for analyst review.
- **`REJECT`**: $p_v < 0.40$ or $\ge 2$ signals strongly contradict $\to$ Reclassified as verified false alarm; dropped from alert feed with evidence logged.

### 3.3 Full Ablation Study Results

To prove that all four signals are strictly necessary, a 9-configuration ablation study was evaluated:

| Configuration | Tested Signals | Weights (r, s, b, e) | Test FPR (%) | Relative FPR Reduction (%) | Recall Retained (%) |
|---|---|---|---|---|---|
| **Config 1 (Full TRUST-SOC)** | **r + s + b + e** | **(0.30, 0.25, 0.25, 0.20)** | **0.0167%** | **98.79%** | **97.60%** |
| Config 2 (No Explanation) | r + s + b | (0.40, 0.30, 0.30, 0.00) | 0.0389% | 97.16% | 96.80% |
| Config 3 (No Behavioural) | r + s + e | (0.40, 0.35, 0.00, 0.25) | 0.0500% | 96.36% | 96.50% |
| Config 4 (No Statistical) | r + b + e | (0.40, 0.00, 0.35, 0.25) | 0.0611% | 95.55% | 95.80% |
| Config 5 (No Rule) | s + b + e | (0.00, 0.35, 0.35, 0.30) | 0.0889% | 93.52% | 94.20% |
| Config 6 (Rule Only) | r | (1.00, 0.00, 0.00, 0.00) | 0.6530% | 52.40% | 98.10% |
| Config 7 (Statistical Only) | s | (0.00, 1.00, 0.00, 0.00) | 0.5320% | 61.20% | 96.40% |
| Config 8 (Behavioural Only) | b | (0.00, 0.00, 1.00, 0.00) | 0.5750% | 58.10% | 95.90% |
| Config 9 (Explanation Only)| e | (0.00, 0.00, 0.00, 1.00) | 0.7230% | 47.30% | 97.80% |

**Ablation Takeaway**: Individual signals achieve only 47%–61% FPR reduction when used in isolation. The full fused 4-signal system achieves **98.79% reduction**, demonstrating multi-modal synergy.

---

## 4. Confidence Scoring & Alert Prioritisation Matrix ($3 \times 3$)

### 4.1 Scoring Formula
$$C = 0.40 p_d + 0.40 p_v + 0.20 r_{\text{corr}}$$

### 4.2 Matrix Distribution on Test Evaluation Split

```text
                  CRITICAL ASSET          HIGH ASSET            NORMAL ASSET
HIGH CONF (C>=0.80)   P1: Page On-Call (4,810)   P1: Urgent Triage (4,250)   P2: Standard Queue (1,940)
MED CONF  (0.50-0.80) P1: Urgent Review (610)    P2: Analyst Queue (580)     P3: Daily Batch (302)
LOW CONF  (C<0.50)    P2: Context Enrich (65)    P3: Auto-Audit (85)         P4: Suppressed (40)
```
- **HIGH Band (Escalated)**: 11,000 alerts (86.74%)
- **MEDIUM Band (Review)**: 1,492 alerts (11.76%)
- **LOW Band (Filtered)**: 190 alerts (1.50%)

---

## 5. Cross-Dataset Generalization on CSE-CIC-IDS2018

### 5.1 Protocol & Rules
- **Zero-Shot Transfer**: Zero refitting of Random Forest, zero refitting of Standard Scaler, zero retuning of verification weights on 2018 data.
- **Port Scan Absence**: Port Scan attack vector is not present in CSE-CIC-IDS2018 (as noted in Stage 5.2). 5 common classes evaluated: `Benign`, `DoS/DDoS`, `Brute Force`, `Web Attack`, `Botnet`.

### 5.2 Signal Breakdown Under Cloud Domain Shift
- **Rule Signal ($r$)**: Extremely robust ($\text{mean} = 0.72$). Port signatures (e.g. 21/22/80) transfer reliably across network environments.
- **Statistical Signal ($s$)**: Moderate domain shift ($\text{mean} = 0.58$). Throughput scale differences between 2017 lab environment and 2018 AWS cloud slightly depress anomaly scores.
- **Behavioural Signal ($b$)**: Adaptive ($\text{mean} = 0.65$). The causal rolling window rapidly adapts to establish normal per-host volume baselines.
- **Explanation Signal ($e$)**: High semantic stability ($\text{mean} = 0.74$). Top SHAP attribution mass remains tightly clustered around true attack features.

---

## 6. System Latency & Operational Throughput

### 6.1 Per-Alert Processing Latency (Hardware: 4-Core x86_64 CPU)

| Pipeline Stage | Median (p50) | 95th Percentile (p95) | 99th Percentile (p99) | Latency Share (%) |
|---|---|---|---|---|
| **1. Ingestion & Normalization** | 0.85 ms | 1.82 ms | 3.10 ms | 0.7% |
| **2. Detection Agent (RF)** | 42.49 ms | 68.20 ms | 88.50 ms | 34.3% |
| **3. SHAP TreeExplainer** | 65.31 ms | 112.40 ms | 145.20 ms | **52.8% (Bottleneck 1)** |
| **4. Verification Agent** | 0.012 ms | 0.025 ms | 0.040 ms | < 0.1% |
| **5. Confidence Scoring** | 0.008 ms | 0.015 ms | 0.025 ms | < 0.1% |
| **6. SQLite Transaction Commit** | 15.06 ms | 28.40 ms | 42.10 ms | 12.1% |
| **Total Live Pipeline** | **123.74 ms** | **200.12 ms** | **268.40 ms** | **100.0% (~8.1 alerts/s)** |
| **7. On-Demand ReportLab PDF** | 40.68 ms | 72.10 ms | 98.40 ms | Rendered on-demand |

### 6.2 Concurrent API Throughput
- **Throughput**: 11.3 requests/second sustained under 4 concurrent worker threads.
- **p50 Response Time**: 47.59 ms.
- **Error Rate**: 0.0% (zero HTTP 500 errors).

---

## 7. Honest Project Limitations & Threats to Validity

1. **False-Negative Incurability**: The Verification Agent only operates on flows classified as threats by the Detection Agent. If an attack flow is misclassified as `Benign` by the baseline model, it never triggers an alert and cannot be recovered by the verification layer.
2. **Asset Context Assumptions**: Criticality levels and whitelists in the benchmark evaluation are configured via static configuration files (`asset_context.json`). In live enterprise networks, dynamic CMDB/Active Directory integration is required.
3. **Explainability Overhead**: TreeExplainer computation represents 52.8% of the live pipeline latency. In multi-gigabit SOC environments, SHAP must be restricted to escalated alerts rather than calculated on every raw flow.
4. **Cloud Domain Shift on Recall**: While cross-dataset FPR reduction was outstanding (96.0%), recall dropped under zero-shot transfer due to strict threshold boundaries. Periodic recalibration on target network data is recommended.
