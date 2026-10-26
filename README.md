# TRUST-SOC: A Trust-Aware, Verification-Driven Detection Pipeline for Security Operations Centers

> **BTech CSE Micro-Project — Milestones 1, 2 & 3 Deliverables**  
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

## 2. End-to-End Pipeline Architecture (Milestones 1, 2 & 3)

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
[6] Confidence Scoring Engine (Stage 3.1 & 3.2)
    C = 0.40 * p_d + 0.40 * p_v + 0.20 * r_corr
              │
              ▼
        HIGH (C >= 0.80) │ MEDIUM (0.50 <= C < 0.80) │ LOW (C < 0.50)
              │
              ├──────────────────────────────┐
              ▼                              ▼
[7] Evidence-Linked Report Generator   [8] SQLite Storage Layer
    (JSON + ReportLab PDF per alert)       (WAL mode, alerts/reports/audit_events)
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
| **Confidence Scoring** | NumPy / pure Python | Fused composite scoring ($C$) and 3x3 Prioritisation Matrix |
| **Reporting** | ReportLab | Publication-quality PDF evidence reports (WeasyPrint NOT used) |
| **Database** | SQLite (`trust_soc.db`) | Relational persistence with WAL concurrency (MongoDB NOT used) |
| **Testing** | stdlib `unittest` | Formal automated test suite (41/41 passing tests) |
| **Optional UI** | Streamlit (`.streamlit/config.toml`) | Milestone 1 light-theme prototype interface |

---

## 4. Light Theme Design Tokens

TRUST-SOC enforces a clean, accessible **light theme** everywhere (visualizations, UI, and PDF reports):

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
--high          #B42318   (red)    Label "HIGH" (C >= 0.80)
--medium        #B54708   (amber)  Label "MEDIUM" (0.50 <= C < 0.80)
--low           #2E7D5B   (green)  Label "LOW" (C < 0.50)

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

---

## 7. Milestone 3: Confidence Scoring, Evidence Reports & Database

### 7.1 Composite Confidence Formula (Section 4.3)

$$C = \alpha \cdot p_d + \beta \cdot p_v + \gamma \cdot r_{\text{corr}}$$
Initial weights: $\alpha = 0.40, \beta = 0.40, \gamma = 0.20$ ($\alpha + \beta + \gamma = 1.0$).

- **HIGH Band ($C \ge 0.80$):** Auto-escalated on SOC dashboard (`AUTO_ESCALATE`).
- **MEDIUM Band ($0.50 \le C < 0.80$):** Queued for analyst triage (`ANALYST_QUEUE`).
- **LOW Band ($C < 0.50$):** Logged with evidence, suppressed from alerting (`LOG_ONLY`).

### 7.2 Alert Prioritisation Matrix (Stage 3.2)

Evaluated on 12,682 test alerts:

| Verification Verdict | $p_d$ HIGH (>=0.80) | $p_d$ MEDIUM (0.50–0.80) | $p_d$ LOW (<0.50) | Operational Triage Action |
|---|:---:|:---:|:---:|---|
| **CONFIRM** | **4,566** (4,566 attacks / 0 FAs) | **7** | **0** | **Urgent Auto-Escalate** / High Priority Queue |
| **REDUCE** | **7,539** (7,539 attacks / 0 FAs) | **24** | **4** | **Suspicious Review** / Standard Queue |
| **REJECT** | **358** (296 attacks / 62 FAs) | **169** | **15** | **Dropped False Alarm** (Audit Logged) |

- **Band Distribution on Test Set:**
  - HIGH Band ($C \ge 0.80$): **11,000 alerts (86.7%)**
  - MEDIUM Band ($0.50 \le C < 0.80$): **1,492 alerts (11.8%)**
  - LOW Band ($C < 0.50$): **190 alerts (1.5%)**

### 7.3 SQLite Relational Storage (`trust_soc.db`)

Managed via `src/database/alert_store.py` with WAL concurrency mode:
- **`alerts`**: Primary alert table with queryable columns (`alert_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `predicted_class`, `detection_probability`, `verification_decision`, `composite_confidence`, `confidence_band`, `status`, `raw_json`).
- **`reports`**: Linked report documents (`report_id`, `alert_id`, `generated_at`, `json_path`, `pdf_path`, `summary`).
- **`audit_events`**: Chronological forensic audit log entries for every lifecycle stage.

### 7.4 Evidence-Linked Report Generator (ReportLab PDF + JSON)

Produces two exports per alert:
1. **JSON Report** (`results/reports/json/{alert_id}.json`): Complete canonical machine-readable payload, MITRE ATT&CK mapping, SHAP feature attributions, and audit trail.
2. **ReportLab PDF Report** (`results/reports/pdf/{alert_id}.pdf`): Light-theme, publication-quality triage document containing:
   - Deep navy executive header banner (`#1F3864`).
   - Triage Summary Card with Confidence and Decision badges.
   - 5-Tuple Network Traffic Context table.
   - Detection Agent class probabilities.
   - Verification Agent 4-signal breakdown and deterministic rationale.
   - SHAP Top-5 feature attribution table.
   - Cryptographic forensic audit timeline.

Sample reports generated:
- `[HIGH] Brute Force (C=0.917, HIGH, CONFIRM)`: `results/reports/pdf/alert-2094afc9_401.pdf`
- `[MEDIUM] Botnet (C=0.747, MEDIUM, REJECT)`: `results/reports/pdf/alert-20d1dc9b_68.pdf`
- `[REJECT] Botnet (C=0.342, LOW, REJECT)`: `results/reports/pdf/alert-f7af2e23_82.pdf`

---

## 8. Canonical Alert Schema Contract (Section 5)

Every replayed, verified, and scored flow produces a compliant Canonical Alert dictionary:

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
  "scoring": {
    "composite": 0.8810,
    "band": "HIGH",
    "components": { "p_d": 0.98, "p_v": 0.8425, "r_corr": 0.90, "alpha": 0.4, "beta": 0.4, "gamma": 0.2 },
    "action": "AUTO_ESCALATE"
  },
  "audit_trail": [
    { "ts": "...", "stage": "ingestion", "event": "Flow record ingested and schema initialized" },
    { "ts": "...", "stage": "detection", "event": "Classified as Port Scan (p=0.98)" },
    { "ts": "...", "stage": "verification", "event": "Verification completed: CONFIRM (p_v=0.8425)" },
    { "ts": "...", "stage": "scoring", "event": "Confidence scored: C=0.8810 (HIGH) -> AUTO_ESCALATE" }
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

# 6. Run live flow-by-flow Log Replay simulation with live verification and SQLite persistence
python run.py replay

# 7. Evaluate Verification Agent & measure FPR reduction on frozen test split
python run.py verify

# 8. Evaluate Confidence Scoring Engine & Prioritisation Matrix
python run.py score

# 9. Generate Evidence Reports in JSON & ReportLab PDF
python run.py report

# 10. Run full automated standard-library unit test suite (41 tests)
python -m unittest discover -s tests -v

# 11. Launch optional Streamlit demo UI (light theme)
streamlit run app/streamlit_app.py
```

---

## 10. Automated Test Suite

Standard library `unittest` suite passing 100% of tests (41/41):

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
test_composite_confidence_bounds (tests.test_scoring)                     ... ok
test_exact_threshold_transitions (tests.test_scoring)                    ... ok
test_monotonicity (tests.test_scoring)                                    ... ok
test_prioritisation_actions (tests.test_scoring)                          ... ok
test_weight_sum_validation (tests.test_scoring)                           ... ok
test_db_stats_aggregation (tests.test_database)                          ... ok
test_insert_and_get_alert (tests.test_database)                          ... ok
test_list_alerts_with_filters (tests.test_database)                      ... ok
test_report_insert_and_retrieval (tests.test_database)                   ... ok
test_update_alert_status (tests.test_database)                           ... ok
test_json_report_generation (tests.test_reporting)                       ... ok
test_pdf_report_generation (tests.test_reporting)                        ... ok
test_both_reports_generation_and_db_link (tests.test_reporting)          ... ok

Ran 41 tests in 1.750s — OK (All tests passing)
```

---

## 11. Milestone 3 Exit Gate Checklist

- [x] Confidence Scoring Engine implemented with verified formula $C = \alpha p_d + \beta p_v + \gamma r_{\text{corr}}$.
- [x] High/Medium/Low confidence bands properly assigned at 0.80 and 0.50 thresholds.
- [x] Alert Prioritisation Matrix ($3 \times 3$ interaction) evaluated on test split.
- [x] SQLite database schema with WAL mode enabled (`alerts`, `reports`, `audit_events`).
- [x] Complete CRUD operations implemented in `alert_store.py`.
- [x] Evidence report generator producing both JSON and ReportLab PDF documents.
- [x] Light theme strictly enforced across all PDF reports (ReportLab).
- [x] MITRE ATT&CK techniques and tactics mapped and embedded in reports.
- [x] Live log replay simulator updated to score and persist alerts.
- [x] CLI entry points `python run.py score` and `python run.py report` operational.
- [x] 100% of unit tests passing in stdlib `unittest` (41/41).
