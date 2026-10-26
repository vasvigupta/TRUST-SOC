# TRUST-SOC: Comprehensive Viva Demo Script (8–10 Minutes)

> **Audience**: Project Guide, External Examiners, Examination Committee  
> **Topic**: TRUST-SOC: A Trust-Aware, Verification-Driven Detection Pipeline for Security Operations Centers  
> **Objective**: Flawless, timed, interactive demonstration of all 6 project stages.

---

## Demo Schedule & Timeline

```text
[0:00 - 1:30]  Problem Statement & Headline Metric (The Alert Fatigue Crisis)
[1:30 - 3:00]  Architecture Overview (Detect -> Verify -> Explain -> Prioritize)
[3:00 - 5:00]  Live SOC Dashboard Tour & Replay Simulator Demonstration
[5:00 - 6:30]  Deep Dive into the Forensic Evidence Drawer (4 Signals + SHAP)
[6:30 - 7:30]  Single Flow Pipeline & ReportLab PDF Evidence Generation
[7:30 - 8:30]  Cross-Dataset Generalization & Ablation Proof
[8:30 - 10:00] Viva Defense & Conclusion (Q&A)
```

---

## Step-by-Step Walkthrough Guide

### [0:00 – 1:30] Introduction & Problem Statement
- **Speaker Action**: Show title slide / README.
- **Talking Points**:
  > "Good morning, respected examiners. Modern Security Operations Centers face catastrophic alert fatigue. Tier-1 analysts are flooded with thousands of security alarms every day, over 95% of which are benign false positives.
  >
  > Traditional ML Intrusion Detection Systems fail because they act as opaque, unverified single-point-of-failure classifiers.
  >
  > **TRUST-SOC** solves this by establishing a second line of defence: an **independent multi-signal verification layer** that checks every detection against rules, statistical anomaly bounds, host behavioural baselines, and semantic SHAP consistency.
  >
  > **Our primary headline achievement**: On the held-out benchmark test split, TRUST-SOC reduced the False-Positive Rate from **1.3721%** down to **0.0167%**—an absolute reduction of **1.3555 percentage points**, representing a **98.79% relative reduction in false alarms**, at a recall cost of only **2.39%**."

---

### [1:30 – 3:00] Pipeline Architecture Overview
- **Speaker Action**: Point to the 6-stage architecture diagram (`docs/architecture.md`).
- **Talking Points**:
  > "The architecture follows a strict 4-step logic:
  > 1. **DETECT**: Fast Random Forest baseline detects candidate attacks ($p_d$).
  > 2. **VERIFY**: An independent Verification Agent corroborates the flow across 4 orthogonal dimensions ($r, s, b, e$) to yield an agreement score $p_v$ and verdict (`CONFIRM`, `REDUCE`, `REJECT`).
  > 3. **EXPLAIN**: SHAP TreeExplainer attributes local directional feature importance.
  > 4. **PRIORITIZE**: A fused confidence formula $C = 0.40 p_d + 0.40 p_v + 0.20 r_{\text{corr}}$ assigns alerts into HIGH, MEDIUM, and LOW operational triage tiers."

---

### [3:00 – 5:00] Live SOC Dashboard Operations
- **Speaker Action**: Open browser to **`http://localhost:8000`**.
- **Actions to Perform**:
  1. Highlight the deep navy **Top Summary Bar**: Show the 98.79% FPR reduction banner and live counters.
  2. Point to the **Replay Controls**: Note the green *SSE Stream Connected* pulse.
  3. Click **"Step 1"** and **"Step 10"**:
     > "Notice as we click 'Step', the controlled-rate replay simulator ingests flows through the complete pipeline in real time. The progress bar advances and newly scored alerts dynamically appear at the top of the table without refreshing the page."
  4. Point to the **Chart.js Visualizations**:
     - *Confidence Bands Doughnut Chart*: Show distribution between High, Medium, and Low.
     - *Threat Categories Bar Chart*: Explain how DoS and Brute Force attacks are validated or reduced.
     - *Operational Prioritisation Matrix*: Show how the $3 \times 3$ grid drives analyst action.

---

### [5:00 – 6:30] Forensic Evidence Drill-Down Drawer
- **Speaker Action**: Click on any alert row in the live table.
- **Actions to Perform**:
  1. Point to the drawer sliding from the right:
     > "Clicking an alert slides open the full forensic audit drawer, preserving analyst situational awareness."
  2. Explain the **5-Tuple Network Context**:
     > "We have source IP, destination IP, ports, protocol, and target server role."
  3. Point to **Side-by-Side Comparison**:
     > "Here is the Detection Agent ($p_d$) on the left, and the Verification Agent ($p_v$) on the right."
  4. Walk through the **4 Independent Signal Breakdown Meters**:
     - *Signal (a) Rule $r$*: Shows port/signature and asset criticality matching.
     - *Signal (b) Statistical $s$*: Shows Isolation Forest anomaly score.
     - *Signal (c) Behavioural $b$*: Shows rolling packet/byte volume $z$-score deviation.
     - *Signal (d) Explanation $e$*: Shows SHAP semantic alignment.
  5. Point to **Deterministic Rationale**:
     > "Notice there is no black-box decision. A clear, deterministic justification explains why the alert was confirmed or reduced."
  6. Point to **SHAP Attribution Mass Drivers**: Show top features driving the alert.
  7. Click **"ACKNOWLEDGED"**: Show the state updating immediately in the SQLite store.

---

### [6:30 – 7:30] Single Flow Pipeline & ReportLab PDF Evidence
- **Speaker Action**:
  1. Click the **"PDF"** button on the alert row or inside the drawer:
     > "Notice how the system renders an audit-ready, light-themed ReportLab PDF report containing cryptographic timestamps, MITRE ATT&CK mapping, and full evidence."
  2. Click **"Single Flow Pipeline"** in the sidebar.
  3. Click **"DoS/DDoS Attack Sample"** and click **"Run Detection"**:
     > "The analyst can paste custom network flow JSON or load test vectors to run the entire pipeline on-demand."

---

### [7:30 – 8:30] Cross-Dataset Generalization & Ablation Proof
- **Speaker Action**: Show [`results/reports/cross_dataset_report.md`](file:///C:/Users/USER/.gemini/antigravity/scratch/TRUST-SOC-fresh/results/reports/cross_dataset_report.md) and [`results/reports/ablation_report.md`](file:///C:/Users/USER/.gemini/antigravity/scratch/TRUST-SOC-fresh/results/reports/ablation_report.md).
- **Talking Points**:
  > "To verify that our models did not overfit, we evaluated zero-shot transfer on CSE-CIC-IDS2018 without any refitting or retuning. The verification layer achieved a **96.00% relative FPR reduction** on 2018 data as well.
  >
  > Furthermore, our 9-configuration ablation study proves that individual signals achieve only 47%–61% FPR reduction, while all 4 signals combined achieve **98.79%**."

---

### [8:30 – 10:00] Conclusion & Ready for Viva Defense
- **Summary Statement**:
  > "In conclusion, TRUST-SOC replaces opaque, single-stage detection with a transparent, verifiable, evidence-linked pipeline that demonstrably solves alert fatigue. All 49 unit tests pass, and the system is fully operational. Thank you, and we welcome your questions."

---

## Contingency / Fallback Plan

| Scenario | Immediate Action |
|---|---|
| Port 8000 in use | Run `uvicorn src.api.main:app --port 8001` and update browser URL. |
| Browser caching old UI | Press `Ctrl + Shift + R` (hard refresh) or open Incognito window. |
| Replay buffer exhausted | Click "Stop" / "Reset" in UI, or run `python run.py pipeline`. |
