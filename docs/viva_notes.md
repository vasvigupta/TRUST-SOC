# TRUST-SOC: Comprehensive Viva Voce Defense Notes & Examiner Q&A

> **Preparation Guide**: BTech CSE Project Viva Voce Examination  
> **System**: TRUST-SOC: A Trust-Aware, Verification-Driven Detection Pipeline for Security Operations Centers  
> **Examiner Persona**: Senior Cyber Security / Machine Learning Faculty / Industry Specialist

---

## Question 1: Why did you choose Random Forest instead of Deep Learning (e.g., LSTMs, 1D-CNNs, or Transformers)?

**Answer**:
> "We chose a Balanced Random Forest for three technical and operational reasons:
> 1. **Tabular Data Superiority**: Tabular flow benchmarks (such as CICFlowMeter outputs) consist of independent statistical aggregations where tree ensembles consistently outperform or match deep neural networks while requiring an order of magnitude fewer parameters.
> 2. **Inference Latency in SOC Pipelines**: In a live SOC environment processing thousands of flows per second, Random Forest evaluates in under **42.5 milliseconds** on standard commodity CPU hardware without requiring dedicated GPU acceleration.
> 3. **Exact Shapley Explanations**: Tree ensembles allow the use of `shap.TreeExplainer`, which computes exact, mathematically rigorous Shapley values in polynomial time $\mathcal{O}(TLD^2)$, whereas deep neural networks require sampling approximations (e.g., KernelSHAP or DeepSHAP) which are computationally prohibitive for real-time triage."

---

## Question 2: Why is False-Positive Rate (FPR) reduction your primary metric instead of raw Accuracy or F1-Score?

**Answer**:
> "In network intrusion detection, class distributions are overwhelmingly imbalanced—typically over 95% to 99% of all real-world flows are benign.
> Under this imbalance, a naive model can achieve **99% accuracy** simply by predicting everything as benign while missing every attack.
> Even with a high accuracy of 99%, an FPR of 1% in an enterprise network generating 10 million flows per day produces **100,000 false alarms every day**. This leads directly to analyst burnout, ignored alerts, and high-severity breaches slipping through.
> Therefore, reducing false alarms on clean benign traffic while retaining true attacks is the single most critical operational metric in real-world SOC operations. That is why our headline result—reducing FPR from **1.3721% to 0.0167%** (a 98.79% relative reduction)—proves direct operational impact."

---

## Question 3: Can the Verification Agent recover False Negatives (attacks missed by the Detection Agent)?

**Answer (Honest Technical Answer)**:
> "No. By architectural design, the Verification Agent is an **inspection layer for candidate alerts**, not an independent flow detector.
> If an attack flow is classified as `Benign` by the baseline Detection Agent, it is treated as normal traffic and does not trigger an alert; hence it never reaches the Verification Agent.
> The purpose of the verification layer is strictly **precision enhancement and false-positive suppression**, protecting human analysts from alert fatigue.
> To address false negatives in future work, an asynchronous background threat-hunting worker or an active anomaly scanner can periodically evaluate a random sample of benign traffic."

---

## Question 4: What is Data Leakage in ML-based IDS, and how did you prevent it?

**Answer**:
> "Data leakage occurs when information from outside the training dataset is inadvertently used to create the model, leading to overly optimistic results that fail in production. We prevented leakage across five strict checkpoints:
> 1. **Split-Before-Fit**: The 70/15/15 train/val/test split was performed **before** computing any preprocessing transformations.
> 2. **Scaler & Imputer Isolation**: `StandardScaler` and `SimpleImputer` were fit **solely on the training split**. The validation, test, and 2018 datasets only called `.transform()`.
> 3. **No Synthetic Oversampling Leakage**: SMOTE was never applied to validation or test splits.
> 4. **Isolation Forest Separation**: The statistical corroboration Isolation Forest was fit **strictly on clean benign training flows** only.
> 5. **Ground Truth Air-Gap**: The `VerificationAgent` class is strictly forbidden from receiving or reading the `ground_truth` dictionary (verified by automated unit tests in `test_verification.py`)."

---

## Question 5: Why is the Port Scan attack class absent in CSE-CIC-IDS2018?

**Answer**:
> "CSE-CIC-IDS2018 was captured by the Canadian Institute for Cybersecurity over ten distinct capture days in an AWS virtual cloud environment. The attack scenarios simulated in 2018 included Brute Force (FTP/SSH), DoS (LOIC, HOIC, Hulk, GoldenEye), Web Attacks (SQLi, XSS), and Botnet (Ares), but **did not execute a dedicated Port Scan scenario**.
> In accordance with academic honesty and Section 14.3 of our specifications, we did not fabricate or simulate a Port Scan class for 2018; we evaluated zero-shot cross-dataset performance strictly across the **5 truly overlapping common classes** and explicitly documented Port Scan as absent."

---

## Question 6: How were the weights for the composite confidence score ($C = 0.40 p_d + 0.40 p_v + 0.20 r_{\text{corr}}$) determined?

**Answer**:
> "The composite confidence formula fuses three complementary signals:
> - $p_d$ (0.40): Detection Agent's probabilistic confidence.
> - $p_v$ (0.40): Multi-signal corroboration agreement score.
> - $r_{\text{corr}}$ (0.20): Normalized rule/context corroboration signal.
>
> We assigned equal $40\%$ weight to the Detection Agent and the Verification Agent because they represent **two independent lines of evidence**: statistical classification versus multi-signal corroboration. The remaining $20\%$ weight was assigned to contextual alignment (asset criticality and port authorization) to ensure high-priority assets receive immediate operational escalation when targeted."

---

## Question 7: What failed or degraded during cross-dataset evaluation on CSE-CIC-IDS2018?

**Answer (Honest Technical Finding)**:
> "Under zero-shot transfer from CICIDS2017 to CSE-CIC-IDS2018:
> 1. **Statistical Anomaly Shift**: The Isolation Forest anomaly scores exhibited distribution shift because AWS cloud infrastructure traffic has different throughput baselines and MTU profiles than the 2017 university lab network.
> 2. **Recall Degradation**: Because decision thresholds ($p_v \ge 0.70$) were frozen from the 2017 validation split, the verification layer classified a higher percentage of attack alerts as `REDUCE` rather than `CONFIRM`.
>
> Rather than artificially retuning weights on the 2018 test data (which would invalidate the cross-dataset scientific claim), we reported this honest finding: under cloud domain shift, the system prudently demotes uncertain alerts to the analyst review queue (`REDUCE`) rather than blindly auto-escalating them."

---

## Question 8: How does TRUST-SOC align with UN Sustainable Development Goals (SDGs)?

**Answer**:
> "TRUST-SOC aligns with two United Nations Sustainable Development Goals:
> - **SDG 9: Industry, Innovation and Infrastructure (Target 9.1 & 9.c)**: By safeguarding enterprise network infrastructure and digital public services against disruptive DoS, brute force, and malware intrusions through trust-aware verification.
> - **SDG 16: Peace, Justice and Strong Institutions (Target 16.6)**: By enforcing transparent, explainable decision-making and immutable cryptographic audit trails in security triage, replacing opaque black-box AI with verifiable, accountable institutions."
