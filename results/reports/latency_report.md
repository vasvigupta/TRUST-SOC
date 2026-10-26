# System Performance & Latency Profiling Report (Milestone 5)

## 1. Hardware Environment
- **Operating System**: Windows 10 (10.0.19045)
- **Processor**: Intel64 Family 6 Model 126 Stepping 5, GenuineIntel (4 cores)
- **Python Version**: 3.13.3 (AMD64)

---

## 2. Stage-by-Stage Latency Breakdown (Per Alert)

| Pipeline Stage | Mean (ms) | p50 / Median (ms) | p95 (ms) | p99 (ms) | Operational Profile |
|---|---|---|---|---|---|
| **1. Ingestion / Schema** | 1.38 | 1.22 | 2.32 | 6.28 | In-memory feature vector normalization |
| **2. Detection Agent (RF)** | 43.94 | 42.49 | 62.60 | 94.34 | 100-tree Random Forest inference |
| **3. SHAP TreeExplainer** | 68.88 | 65.31 | 110.92 | 134.52 | **Primary Live Bottleneck** (feature attribution) |
| **4. Verification Agent** | 0.02 | 0.01 | 0.02 | 0.17 | 4-signal corroboration (r, s, b, e) |
| **5. Confidence Scoring** | 0.05 | 0.04 | 0.07 | 0.08 | Fused equation + band mapping (<0.1ms) |
| **6. SQLite Persistence** | 17.22 | 15.29 | 25.91 | 49.72 | WAL-mode transaction commit |
| **Total Live Pipeline** | **131.49** | **123.74** | **200.12** | **224.67** | **8.1 alerts/second** throughput |
| **7. On-Demand PDF (ReportLab)** | 40.70 | 40.68 | 50.88 | 54.27 | Rendered strictly on analyst download request |

---

## 3. Concurrent API Responsiveness Under Load

- **Simulated Concurrent Workers**: 4 threads
- **Total Requests**: 60 (60 successful, 0 errors)
- **API Throughput**: **11.3 req/sec**
- **Median Response Time (p50)**: **47.59 ms**
- **95th Percentile Response Time (p95)**: **3334.89 ms**
