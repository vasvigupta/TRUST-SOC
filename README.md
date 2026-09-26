# TRUST-SOC
## Trust-Aware, Verification-Driven Detection Pipeline for Security Operations Centers

> **BTech CSE Micro-Project — First Review Prototype**  
> **Detection Agent**: Random Forest baseline & XGBoost alternative | **Dataset**: CICIDS2017  
> **Explainability**: SHAP | **Backend / API**: FastAPI | **Data Store**: SQLite | **Reports**: ReportLab PDF  
> **Dashboard**: React.js + Chart.js (Light Theme) | **Docs & Analysis**: Jupyter Notebooks

---

## 1. System Architecture

```text
CICIDS2017 Network Flows (Historical & Stream Simulator)
           │
           ▼
[ Preprocessing Pipeline ]  (Clean, Scale, Stratify, 6-Class Mapping)
           │
           ▼
[ Detection Agent ]  (Random Forest Classifier + XGBoost Alternative)
           │
           ▼
[ Explainability Engine ]  (SHAP TreeExplainer Feature Attributions)
           │
           ▼
[ SQLite Persistence & ReportLab PDF Engine ]  (trust_soc.db & Evidentiary PDF)
           │
           ▼
[ FastAPI Backend REST API ]  (Port 8000)
           ▲
           │ JSON REST / Event Stream
           ▼
[ React.js + Chart.js Dashboard ]  (Port 5173 / 3000, Clean Light Theme)
```

---

## 2. Technology Stack Mapping

| Layer | Technology | Role & Purpose |
|---|---|---|
| **Programming Language** | Python 3.11 | Core implementation for all agents, pipelines, and APIs |
| **Data Handling** | Pandas, NumPy | Dataset loading, cleaning, feature transformation, statistics |
| **Machine Learning** | scikit-learn, XGBoost | Detection Agent classification & Isolation Forest stub |
| **Explainability** | SHAP | Feature-attribution for Detection Agent verdicts |
| **Log Ingestion / Streaming** | Python generator / queue simulator | Controlled-rate replay of historical flows as simulated live stream |
| **Backend / API** | FastAPI + Uvicorn | High-performance REST endpoints serving predictions, alerts & metrics |
| **Data Store** | SQLite (`trust_soc.db`) | Relational persistence of generated alerts, timestamps & states |
| **Report Generation** | ReportLab | Programmatic generation of evidence-linked PDF reports per alert |
| **Dashboard / Frontend** | React.js + Chart.js | Modern SOC dashboard: alert feed, live detection, charts & replay |
| **Datasets** | CICIDS2017 | Multi-class intrusion detection dataset mapped to 6 canonical classes |
| **Docs & Experimentation** | Jupyter Notebooks | Interactive step-by-step notebooks (Exploration, Preprocessing, Detection, SHAP) |

---

## 3. Project Structure

```text
TRUST-SOC/
├── data/
│   ├── raw/CICIDS2017/          # Primary raw CSV files
│   ├── processed/               # Leakage-free train/val/test parquet splits
│   └── sample/                  # Stream replay sample
├── notebooks/                   # Jupyter Notebooks for analysis & audit
│   ├── 01_data_exploration.ipynb
│   ├── 02_preprocessing.ipynb
│   ├── 03_detection_agent.ipynb
│   └── 04_shap_analysis.ipynb
├── src/
│   ├── api/                     # FastAPI REST API
│   │   ├── routes/              # /detect, /alerts, /metrics, /reports
│   │   ├── schemas.py           # Pydantic models
│   │   └── main.py              # Application factory & CORS
│   ├── config/config.py         # Centralized hyperparameters & paths
│   ├── database/                # SQLite connection & CRUD operations
│   │   ├── db.py
│   │   └── alert_store.py
│   ├── detection/               # Detection Agent (RF & XGBoost)
│   │   ├── model.py
│   │   ├── train.py
│   │   └── predict.py
│   ├── explainability/          # SHAP TreeExplainer module
│   │   └── shap_explainer.py
│   ├── ingestion/               # Log replay streaming engine
│   │   └── log_replay.py
│   ├── preprocessing/           # Data cleaning & stratified split
│   │   └── preprocess.py
│   ├── reporting/               # ReportLab PDF evidence generator
│   │   └── pdf_report.py
│   └── verification/            # Verification Agent extension stub
│       └── verification_agent.py
├── frontend/                    # React.js + Chart.js Dashboard (Vite)
│   ├── src/
│   │   ├── components/          # MetricsBar, AlertCard, FeatureChart
│   │   ├── pages/               # Dashboard, Detection, Alerts, Replay
│   │   ├── api.js               # Axios client
│   │   └── App.jsx
│   └── package.json
├── models/                      # Saved trained models (.joblib)
├── results/                     # Baseline evaluation metrics, confusion matrix & SHAP
├── tests/                       # Pytest test suite (35 tests passing)
├── trust_soc.db                 # SQLite database file
├── run.py                       # CLI master runner
└── requirements.txt
```

---

## 4. Quickstart: Running the System

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
cd frontend && npm install && cd ..
```

### Step 2: Run Backend Pipeline & Start FastAPI
```bash
# Execute ML pipeline (preprocessing, training, evaluation, SHAP)
python run.py --stage all

# Start FastAPI server on http://localhost:8000
python run.py --stage api
```
Interactive API docs available at: `http://localhost:8000/docs`

### Step 3: Start React.js Dashboard
In another terminal:
```bash
cd frontend
npm run dev
```
Open **`http://localhost:5173`** (or port specified in terminal) in your browser.

---

## 5. Verification Agent Extension Contract

As required for this prototype stage:
- **Detection Agent**: Random Forest baseline is fully trained, evaluated, and explained with SHAP.
- **Verification Agent**: Exists as an architecturally clean extension stub (`src/verification/verification_agent.py`) returning `NOT_IMPLEMENTED`.
- Evaluation metrics explicitly represent the unverified Detection Agent baseline for comparison in Phase 2.
