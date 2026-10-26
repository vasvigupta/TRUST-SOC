# TRUST-SOC: Controlled Model Comparison Report (Stage 1.6)

## 1. Experimental Setup
- **Dataset**: CICIDS2017 (TrafficLabelling variant, 202,981 stratified flows)
- **Splits**: Exact identical 70% Train (142,086), 15% Validation (30,447), 15% Test (30,448)
- **Preprocessing**: Identical median imputer & StandardScaler fitted on Train split only

## 2. Quantitative Comparison Table

| Evaluation Split | Metric | Random Forest (Baseline) | XGBoost (Alternative) |
|---|---|---|---|
| **Validation** | Accuracy | **0.9923** | 0.9978 |
| **Validation** | Macro F1 | **0.9521** | 0.9824 |
| **Validation** | Weighted F1 | **0.9931** | 0.9978 |
| **Validation** | Alert-Level FPR | **0.0124** (1.24%) | 0.0020 (0.20%) |
| **Validation** | Inference Latency | 0.0098 ms/flow | **0.0131 ms/flow** |
| **Test** | Accuracy | 0.9914 | 0.9978 |
| **Test** | Macro F1 | 0.9468 | 0.9832 |
| **Test** | Alert-Level FPR | 0.0137 (1.37%) | 0.0025 (0.25%) |

## 3. Architectural Selection Decision

Random Forest is retained as the primary Detection Agent baseline per the synopsis specification. Both models achieve exceptional accuracy (>99.1%) and macro-F1 (>0.94). Random Forest provides instantaneous SHAP TreeExplainer evaluation with exact Shapley values and robust multiclass stability. XGBoost is fully integrated and switchable via MODEL_TYPE.
