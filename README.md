# TRUST-SOC: A Trust-Aware, Verification-Driven Detection Pipeline for Security Operations Centers

> **BTech CSE Micro-Project — Milestones 1 & 2 Deliverables**  
> **Team**: Madhav Bhardwaj, Vasvi Gupta, Anushka Saxena  
> **Project Guide**: Mr. Mohit Tiwari  
> **Institution**: Bharati Vidyapeeth's College of Engineering (BVCOE), New Delhi  

---

## 1. Project Overview & Problem Statement

Modern Security Operations Centers (SOCs) face overwhelming **alert fatigue**. Analysts are inundated with thousands of security events per day, the majority of which are false alarms. Traditional Machine Learning Intrusion Detection Systems (IDS) suffer from five core deficiencies:

1. **No second line of defence against false positives**: Standalone classifiers lack independent verification.
2. **Opaque verdicts**: Alerts output an attack label and probability, but fail to provide semantic, verifiable explanations.
3. **No audit trail linking alerts to evidence**: Raw packet/flow evidence is separated from the triage decision.
4. **No confidence-based prioritisation**: Alerts lack fused scoring that incorporates context and multi-signal corroboration.
5. **Lack of operational interfaces**: Academic IDS research rarely integrates with usable, accessible SOC dashboards.

**TRUST-SOC** introduces a four-step pipeline:
```text
DETECT  ──►  VERIFY  ──►  EXPLAIN  ──►  PRIORITIZE
```

**Primary Success Metric of the Project:**
> Measurable reduction in False-Positive Rate (FPR) after independent verification, compared with the Detection Agent baseline alone — reported as absolute and percentage reductions alongside the measured recall cost.

---

## 2. End-to-End Pipeline Architecture (Milestones 1 & 2)

```text
CICIDS2017 (TrafficLabelling / GeneratedLabelledFlows CSVs)
              │
              ▼
[1] Dataset Exploration & Quality Audit (Stage 1.1)
              │
              ▼
[2] Preprocessing & Stratification (Stage 1.3)
    (Leakage-free, Median Imputer + StandardScaler fit on Train only)
              │
              ▼
[3] Detection Agent (Stage 1.4 & 1.6)
    (Random Forest Baseline | XGBoost Switchable Alternative)
              │  Predictions + Raw Probability p_d
              ▼
[4] Explainability Engine (Stage 1.7)
    (SHAP TreeExplainer Top-k Feature Attributions)
              │  Predictions + Top Features
              ▼
[5] Verification Agent — CORE TRUST MECHANISM (Stage 2.1–2.6)
     ├─ (a) Rule / context corroboration (r)
     ├─ (b) Statistical corroboration via Isolation Forest (s)
     ├─ (c) Behavioural baseline check with causal sliding window (b)
     └─ (d) Explanation-consistency check via SHAP semantic alignment (e)
              │  Agreement score p_v = 0.30r + 0.25s + 0.25b + 0.20e
              ▼
        CONFIRM  │  REDUCE  │  REJECT
              │
              ▼
[6] Canonical Log Replay & Audit Feed (Stage 1.8 & 2.6)
    (Python generator + queue.Queue -> Canonical Alert Schema with full audit trail)
```

---

## 3. Technology Stack (Locked)

| Component | Technology | Purpose |
|---|---|---|
| **Language** | Python 3.13 | Core detection agents, verification signals, pipeline, and CLI |
| **Data Handling** | Pandas, NumPy | Chunked loading, cleaning, feature engineering |
| **Machine Learning** | scikit-learn, XGBoost | Random Forest baseline, XGBoost alternative; Isolation Forest anomaly model |
| **Explainability** | SHAP (`shap.TreeExplainer`) | Fast, exact Shapley feature attributions |
| **Streaming / Ingestion** | Python generator + `queue.Queue` | Memory-bounded, Kafka-compatible replay |
| **Testing** | stdlib `unittest` | Formal automated test suite (28 tests) |
| **Storage / DB** | SQLite (`trust_soc.db`) | Relational persistence of alerts and reports |
| **Optional UI** | Streamlit (`.streamlit/config.toml`) | Light-theme prototype interface |

---

## 4. Light Theme Design Tokens

TRUST-SOC enforces a clean, accessible **light theme** everywhere (visualizations, UI, and future PDF reports):

```text
--bg            #F7F9FC   Page background
--surface       #FFFFFF   Cards, tables, surfaces
--border        #D9E0EA   Dividers and borders
--text          #1F2937   Primary dark body text (WCAG AA compliant)
--text-muted    #5B6676   Secondary / metadata text
--primary       #1F3864   Deep navy (matches synopsis headers)
--primary-soft  #E8EEF8   Soft navy container tint
--accent        #2F6FB3   Interactive blue accent

Confidence Bands:
--high          #B42318   (red)    Label "HIGH"
--medium        #B54708   (amber)  Label "MEDIUM"
--low           #2E7D5B   (green)  Label "LOW"

Verification Decisions:
CONFIRM         #1F6F43   (forest green)  Verified attack alert
REDUCE          #B54708   (amber)         Partial agreement / suspicious
REJECT          #5B6676   (muted grey)    Verified false positive dropped
```

---

## 5. Milestone 2: Verification Agent & The Trust Mechanism

The Verification Agent serves as a genuinely independent second opinion, rejecting false positives generated by ML detection agents while maintaining attack recall.

### 5.1 The Four Independent Signals

Every signal operates independently, returns a float in $[0, 1]$ ($1 = \text{corroborates attack}, 0 = \text{contradicts}$), flags strong contradictions ($< 0.20$), and **never inspects ground truth or the detection probability $p_d$**:

1. **Signal (a) Rule / Context Corroboration ($r$)**:
   - Matches target ports against expected attack signatures (e.g., FTP 21 / SSH 22 for Brute Force, Web 80/443/8080 for Web Attack / DoS).
   - Maps to MITRE ATT&CK techniques (T1498, T1046, T1110, T1190, T1071).
   - Checks asset criticality inventory (`192.168.10.50` Ubuntu Web Server, `192.168.10.3` Domain Controller).
   - Enforces infrastructure whitelists (penalizes alerts on normal DNS queries).

2. **Signal (b) Statistical Corroboration ($s$)**:
   - `IsolationForest` trained **strictly on Benign training traffic only**.
   - Anomaly score calibrated against benign training split percentiles ($q_{01}, q_{95}$).
   - Assigns low scores ($< 0.20$) to traffic conforming to the benign manifold, directly identifying statistical false alarms.

3. **Signal (c) Behavioural Baseline Check ($b$)**:
   - Host-level baseline profiles (mean and std of packet rate, byte volume, duration, packet length) computed from benign training traffic across 151 frequent hosts with a global fallback.
   - Maintains a **causal rolling window** (bounded deque, max depth 50) per host.
   - Computes flow and burst deviations; updates rolling state strictly **after** scoring to prevent future data leakage.

4. **Signal (d) Explanation Consistency Check ($e$)**:
   - Maps top-k SHAP attribution features to domain knowledge feature families defined in `src/config/rules.json`.
   - Computes the ratio of attribution mass aligned with attack physics (e.g., packet rate/duration for DoS vs. flags/segment sizes).
   - Contradicts alerts where predictions are driven by spurious artifacts.

### 5.2 Formal Decision Table

Agreement score:
$$p_v = 0.30\,r + 0.25\,s + 0.25\,b + 0.20\,e$$

| Decision | Condition | Operational Effect |
|---|---|---|
| **CONFIRM** | $p_v \ge 0.70$ and 0 signals strongly contradictory ($< 0.20$) | Alert validated; passes to composite confidence scoring at full weight |
| **REDUCE** | $0.40 \le p_v < 0.70$, or 1 signal strongly contradictory | Retained but flagged "Suspicious — Needs Review" for analyst triage |
| **REJECT** | $p_v < 0.40$, or $\ge 2$ signals strongly contradictory ($< 0.20$) | Verified false alarm; dropped from escalation and logged with evidence |

---

## 6. Primary Success Metric Results (Frozen Test Set)

Evaluated strictly once on the held-out test split (30,448 flows: 18,001 benign, 12,447 attack):

| Evaluation Metric | Standalone Detection Agent (Baseline) | Post-Verification (Lenient: Conf+Red) | Post-Verification (Strict: Confirm Only) |
|---|:---:|:---:|:---:|
| **False Alarms (on Benign Traffic)** | **247** | **3** | **0** |
| **False Positive Rate (FPR)** | **1.3721%** | **0.0167%** | **0.0000%** |
| **Absolute FPR Reduction** | — | **1.3555 percentage points** | **1.3721 percentage points** |
| **Relative FPR Reduction (%)** | — | **98.79%** | **100.00%** |
| **True Attacks Retained** | 12,435 | 12,137 | 4,573 |
| **Recall Cost** | — | **2.39%** | 63.26% |
| **Cohen's Kappa Agreement** | — | **0.608** | — |

### Per-Class False Alarm Breakdown (Frozen Test Set)

| Predicted Class | Baseline False Alarms | Rejected False Alarms | FA Reduction (%) | Baseline Attack Alerts | Attacks Retained | Retention Rate (%) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Botnet** | 217 | 217 | **100.0%** | 293 | 5 | 1.71% |
| **Brute Force** | 9 | 9 | **100.0%** | 2,073 | 2,063 | **99.52%** |
| **DoS/DDoS** | 6 | 3 | **50.0%** | 5,999 | 5,999 | **100.00%** |
| **Port Scan** | 0 | 0 | **100.0%** | 3,748 | 3,748 | **100.00%** |
| **Web Attack** | 15 | 15 | **100.0%** | 322 | 322 | **100.00%** |
| **Total** | **247** | **244** | **98.79%** | **12,435** | **12,137** | **97.60%** |

> **Scientific Honesty Note on Recall Cost**: The 2.39% recall cost is driven almost exclusively by Botnet traffic in CICIDS2017 (Ares keepalive packets), which closely mimic benign beaconing. For all other attack classes (DoS, Port Scan, Web Attack, Brute Force), attack retention is **99.5% to 100.0%**.

---

## 7. Validation Split Ablation Study

Evaluated across 12,660 validation alerts (223 baseline false alarms, 12,437 true attacks):

| Configuration | FA Rejected | FA Remaining (Lenient) | Post FPR (Lenient) | Rel FPR Reduction (%) | Attacks Retained | Recall Cost (%) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Signal (a) Alone [Rule]** | 167 | 56 | 0.311% | **74.9%** | 12,436 | 0.01% |
| **Signal (b) Alone [Statistical]** | 221 | 2 | 0.011% | **99.1%** | 4,101 | 66.97% |
| **Signal (c) Alone [Behavioural]** | 217 | 6 | 0.033% | **97.3%** | 11,373 | 8.55% |
| **Signal (d) Alone [Explanation]** | 151 | 72 | 0.400% | **67.7%** | 11,517 | 7.39% |
| **Leave-One-Out: Without (a)** | 220 | 3 | 0.017% | **98.7%** | 11,064 | 11.03% |
| **Leave-One-Out: Without (b)** | 179 | 44 | 0.244% | **80.3%** | 12,423 | 0.11% |
| **Leave-One-Out: Without (c)** | 179 | 44 | 0.244% | **80.3%** | 11,800 | 5.12% |
| **Leave-One-Out: Without (d)** | 220 | 3 | 0.017% | **98.7%** | 11,976 | 3.70% |
| **Full Fused Mechanism (a+b+c+d)** | **220** | **3** | **0.017%** | **98.7%** | **12,149** | **2.31%** |

---

## 8. Canonical Alert Schema Contract (Section 5)

Every replayed and verified flow produces a compliant Canonical Alert dictionary:

```json
{
  "schema_version": "1.0",
  "alert_id": "alert-b8f2c3d4:42",
  "ingested_at": "2026-10-26T21:12:00Z",
  "flow": {
    "source_file": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "row_index": 42,
    "fields_available": {
      "Source IP": "172.16.0.1",
      "Destination IP": "192.168.10.50",
      "Source Port": 49812,
      "Destination Port": 80,
      "Protocol": 6,
      "Timestamp": "07/07/2017 01:00:00"
    },
    "features": { "Flow Duration": 48.0, "Flow Packets/s": 41666.67, ... }
  },
  "detection": {
    "model": "random_forest",
    "predicted_class": "Port Scan",
    "probability": 0.98,
    "class_probabilities": { "Port Scan": 0.98, "Benign": 0.02, ... },
    "top_features": [
      { "rank": 1, "feature": "Flow Duration", "shap_value": 0.38, "feature_value": 48.0 }
    ],
    "is_alert": true
  },
  "verification": {
    "decision": "CONFIRM",
    "p_v": 0.8425,
    "signals": {
      "rule": { "score": 0.90, "strongly_contradictory": false, "details": { ... } },
      "statistical": { "score": 0.82, "strongly_contradictory": false, "details": { ... } },
      "behavioural": { "score": 0.78, "strongly_contradictory": false, "details": { ... } },
      "explanation": { "score": 0.88, "strongly_contradictory": false, "details": { ... } }
    },
    "rationale": "Decision CONFIRM (agreement p_v=0.842). Strong multi-signal consensus corroborates attack..."
  },
  "scoring": { "composite": 0.0, "band": "LOW" },
  "audit_trail": [
    { "ts": "...", "stage": "ingestion", "event": "Flow record ingested and schema initialized" },
    { "ts": "...", "stage": "detection", "event": "Classified as Port Scan (p=0.98)" },
    { "ts": "...", "stage": "verification", "event": "Verification completed: CONFIRM (p_v=0.8425)" }
  ],
  "ground_truth": { "original_label": "PortScan", "project_class": "Port Scan", "is_attack": true }
}
```

---

## 9. How to Run the Project

### Prerequisites
- Python 3.11+ (tested on Python 3.13)
- Dependencies installed from `requirements.txt`:
```bash
pip install -r requirements.txt
```

### CLI Subcommands
Execute any stage via the master `run.py` CLI:

```bash
# 1. Dataset exploration & data quality audit
python run.py explore

# 2. Preprocess data, clean, and create stratified splits
python run.py preprocess

# 3. Train the Random Forest Detection Agent baseline
python run.py train

# 4. Evaluate baseline metrics & alert-level FPR on held-out test split
python run.py evaluate

# 5. Run SHAP global and per-prediction explainability analysis
python run.py explain

# 6. Run live flow-by-flow Log Replay simulation with Verification Agent
python run.py replay

# 7. Evaluate Verification Agent & measure FPR reduction on frozen test split
python run.py verify

# 8. Run full automated standard-library unit test suite (28 tests)
python -m unittest discover -s tests -v

# 9. Launch optional Streamlit demo UI (light theme)
streamlit run app/streamlit_app.py
```

---

## 10. Automated Test Suite

Standard library `unittest` suite passing 100% of tests (28/28):

```text
test_detect_single_flow_interface (tests.test_detection)                 ... ok
test_model_loaded (tests.test_detection)                                 ... ok
test_predict_proba_sums_to_one (tests.test_detection)                    ... ok
test_predict_shape_and_classes (tests.test_detection)                    ... ok
test_shap_reconstruction_consistency (tests.test_explainability)         ... ok
test_single_flow_explanation_contract (tests.test_explainability)        ... ok
test_artifacts_exist (tests.test_preprocessing)                          ... ok
test_imputer_and_scaler_fitted (tests.test_preprocessing)                ... ok
test_label_mapping (tests.test_preprocessing)                            ... ok
test_no_target_leakage_columns (tests.test_preprocessing)                ... ok
test_split_dimensions_and_no_leakage (tests.test_preprocessing)          ... ok
test_next_n_returns_exact_count (tests.test_replay)                      ... ok
test_next_returns_valid_alert (tests.test_replay)                        ... ok
test_rate_adjustment (tests.test_replay)                                 ... ok
test_schema_rejects_invalid_probability (tests.test_schema_and_isolation) ... ok
test_schema_rejects_missing_keys (tests.test_schema_and_isolation)        ... ok
test_strict_ground_truth_isolation (tests.test_schema_and_isolation)     ... ok
test_valid_alert_schema (tests.test_schema_and_isolation)                ... ok
test_confirm_decision (tests.test_verification)                          ... ok
test_reduce_decision_partial_disagreement (tests.test_verification)      ... ok
test_reject_decision_multiple_contradictions (tests.test_verification)   ... ok
test_reject_decision_score_below_threshold (tests.test_verification)     ... ok
test_ground_truth_isolation (tests.test_verification)                   ... ok
test_behavioural_signal_causal_integrity (tests.test_verification)       ... ok
test_explanation_signal_contract_and_bounds (tests.test_verification)   ... ok
test_rule_signal_contract_and_bounds (tests.test_verification)          ... ok
test_rule_signal_whitelisted_dns_contradiction (tests.test_verification) ... ok
test_statistical_signal_contract_and_bounds (tests.test_verification)   ... ok

Ran 28 tests in 1.514s — OK (All tests passing)
```

---

## 11. Milestone 2 Exit Gate Checklist

- [x] All 4 verification signals implemented with strict contract adherence ($[0, 1]$, strong contradiction flag, details dict).
- [x] Zero inspection of `ground_truth` by any signal or verification agent method (verified by unit test).
- [x] Strict independence: signals $r, s, b$ form their opinions without inspecting $p_d$.
- [x] Isolation Forest trained strictly on benign training flows only.
- [x] Host behavioural baselines built from benign training traffic only; rolling window causally respects time.
- [x] Decision table matches Section 4.2: CONFIRM, REDUCE, REJECT.
- [x] Deterministic rationale generated from signal consensus/discordance templates.
- [x] Signal weights and thresholds tuned exclusively on the Validation split.
- [x] Full ablation study executed and documented (`ablation_summary.json` and `ablation_report.md`).
- [x] Frozen test split evaluated strictly once with verified primary success metric:
  - Baseline FPR: **1.3721%** (247 false alarms)
  - Post-Verification Lenient FPR: **0.0167%** (3 false alarms)
  - **Relative FPR Reduction: 98.79%**
  - **Absolute FPR Reduction: 1.3555 percentage points**
  - Recall Cost: **2.3942%**
  - Cohen's Kappa: **0.608**
- [x] Light-theme comparative visualization saved to `results/verification/fpr_reduction.png`.
- [x] CLI entry point `python run.py verify` operational.
- [x] 100% of unit tests passing in stdlib `unittest` (28/28).
