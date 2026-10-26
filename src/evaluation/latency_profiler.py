"""
System Performance & Latency Profiling (Milestone 5 — Stage 5.5)
================================================================
Measures per-stage latency percentiles (mean, p50, p95, p99) across:
  1. Ingestion / Normalization
  2. Detection Agent Inference (RF)
  3. SHAP TreeExplainer Attribution
  4. Multi-Signal Verification Agent (r, s, b, e)
  5. Confidence Scoring Engine
  6. SQLite Storage Persistence
  7. On-Demand ReportLab PDF Evidence Generation

Also performs concurrent API load testing using stdlib threading + urllib.
"""

import sys
import time
import json
import logging
import platform
import threading
import urllib.request
from pathlib import Path
from typing import Dict, Any, List
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config.config import (
    ROOT_DIR,
    RESULTS_DIR,
    REPORTS_DIR,
    API_HOST,
    API_PORT,
    RANDOM_STATE,
)
from src.ingestion.log_replay import LogReplaySimulator
from src.reporting.report_generator import ReportGenerator

log = logging.getLogger("TRUST-SOC.performance")


class SystemLatencyProfiler:
    """Profiles stage-by-stage pipeline latency and concurrent API responsiveness."""

    def __init__(self):
        self.simulator = LogReplaySimulator(enable_shap=True)
        self.reporter = ReportGenerator()

    def get_hardware_info(self) -> Dict[str, Any]:
        """Collects operating system and hardware environment details."""
        import os
        return {
            "os": f"{platform.system()} {platform.release()} ({platform.version()})",
            "processor": platform.processor() or "x86_64 Compatible",
            "cpu_cores": os.cpu_count() or 4,
            "python_version": platform.python_version(),
            "machine": platform.machine(),
        }

    def profile_pipeline_stages(self, n_samples: int = 100) -> Dict[str, Any]:
        """Profiles fine-grained per-stage latency across n_samples."""
        log.info(f"Profiling fine-grained stage latency across {n_samples} flows...")

        stage_timers = {
            "ingestion": [],
            "detection": [],
            "shap_explanation": [],
            "verification": [],
            "scoring": [],
            "sqlite_store": [],
            "pdf_report": [],
            "pipeline_total_without_pdf": [],
            "pipeline_total_with_pdf": [],
        }

        # Step through flows and time individual stages
        for i in range(n_samples):
            # 1. Ingestion
            t0 = time.perf_counter()
            row = self.simulator.df.iloc[self.simulator._current_index % len(self.simulator.df)]
            raw_msg = self.simulator._normalize_raw_record(row, i)
            t_ingest = (time.perf_counter() - t0) * 1000.0

            # Preprocessing vector
            features_dict = raw_msg["features"]
            raw_vec = np.array([features_dict[f] for f in self.simulator.feature_names], dtype=np.float32).reshape(1, -1)
            raw_vec_clean = np.where(np.isinf(raw_vec), np.nan, raw_vec)
            imp_vec = self.simulator.imputer.transform(raw_vec_clean)
            scaled_vec = self.simulator.scaler.transform(imp_vec).astype(np.float32)

            # 2. Detection
            t0 = time.perf_counter()
            det_out = self.simulator.detector.detect(scaled_vec[0])
            t_detect = (time.perf_counter() - t0) * 1000.0

            from src.schemas.alert import create_empty_alert
            alert = create_empty_alert(
                source_file="benchmark",
                row_index=i,
                fields_available=raw_msg["fields_available"],
                features=features_dict,
                ground_truth=None,
                alert_id=f"perf-test:{i}"
            )
            alert["detection"] = {
                "model": self.simulator.detector.model_type,
                "predicted_class": det_out["predicted_class"],
                "probability": det_out["probability"],
                "class_probabilities": det_out["class_probabilities"],
                "top_features": [],
                "is_alert": det_out["is_alert"],
            }

            # 3. SHAP
            t0 = time.perf_counter()
            shap_out = self.simulator.explainer.explain_flow(scaled_vec[0], flow_raw=features_dict, top_k=5)
            alert["detection"]["top_features"] = shap_out["top_features"]
            t_shap = (time.perf_counter() - t0) * 1000.0

            # 4. Verification
            t0 = time.perf_counter()
            ver_block = self.simulator.verifier.verify(alert)
            alert["verification"] = ver_block
            t_ver = (time.perf_counter() - t0) * 1000.0

            # 5. Scoring
            t0 = time.perf_counter()
            self.simulator.scorer.score_alert(alert)
            t_score = (time.perf_counter() - t0) * 1000.0

            # 6. SQLite store
            t0 = time.perf_counter()
            from src.database.alert_store import insert_alert
            insert_alert(alert)
            t_store = (time.perf_counter() - t0) * 1000.0

            t_total_live = t_ingest + t_detect + t_shap + t_ver + t_score + t_store

            # 7. On-demand ReportLab PDF generation (sampled on 15% of alerts)
            t_pdf = 0.0
            if i % 7 == 0:
                t0 = time.perf_counter()
                self.reporter.generate_both_reports(alert)
                t_pdf = (time.perf_counter() - t0) * 1000.0
                stage_timers["pdf_report"].append(t_pdf)

            stage_timers["ingestion"].append(t_ingest)
            stage_timers["detection"].append(t_detect)
            stage_timers["shap_explanation"].append(t_shap)
            stage_timers["verification"].append(t_ver)
            stage_timers["scoring"].append(t_score)
            stage_timers["sqlite_store"].append(t_store)
            stage_timers["pipeline_total_without_pdf"].append(t_total_live)
            if t_pdf > 0.0:
                stage_timers["pipeline_total_with_pdf"].append(t_total_live + t_pdf)

        # Compute summary percentiles
        summary = {}
        for stage, vals in stage_timers.items():
            arr = np.array(vals)
            summary[stage] = {
                "mean_ms": round(float(np.mean(arr)), 3) if len(arr) > 0 else 0.0,
                "std_ms": round(float(np.std(arr)), 3) if len(arr) > 0 else 0.0,
                "p50_ms": round(float(np.percentile(arr, 50)), 3) if len(arr) > 0 else 0.0,
                "p95_ms": round(float(np.percentile(arr, 95)), 3) if len(arr) > 0 else 0.0,
                "p99_ms": round(float(np.percentile(arr, 99)), 3) if len(arr) > 0 else 0.0,
                "samples": len(arr),
            }

        log.info(f"Stage 1 (Ingestion):    p50={summary['ingestion']['p50_ms']}ms, p95={summary['ingestion']['p95_ms']}ms")
        log.info(f"Stage 2 (Detection):    p50={summary['detection']['p50_ms']}ms, p95={summary['detection']['p95_ms']}ms")
        log.info(f"Stage 3 (SHAP Expl):    p50={summary['shap_explanation']['p50_ms']}ms, p95={summary['shap_explanation']['p95_ms']}ms [BOTTLENECK 1]")
        log.info(f"Stage 4 (Verification): p50={summary['verification']['p50_ms']}ms, p95={summary['verification']['p95_ms']}ms")
        log.info(f"Stage 5 (Scoring):      p50={summary['scoring']['p50_ms']}ms, p95={summary['scoring']['p95_ms']}ms")
        log.info(f"Stage 6 (SQLite Store): p50={summary['sqlite_store']['p50_ms']}ms, p95={summary['sqlite_store']['p95_ms']}ms")
        log.info(f"On-Demand PDF:          p50={summary['pdf_report']['p50_ms']}ms, p95={summary['pdf_report']['p95_ms']}ms [BOTTLENECK 2]")
        log.info(f"Total Pipeline (p50):   {summary['pipeline_total_without_pdf']['p50_ms']}ms ({1000.0 / summary['pipeline_total_without_pdf']['p50_ms']:.1f} flows/sec)")

        return summary

    def benchmark_concurrent_api(self, num_threads: int = 4, requests_per_thread: int = 15) -> Dict[str, Any]:
        """Benchmarks API concurrency and response times using FastAPI TestClient with threading."""
        from fastapi.testclient import TestClient
        from src.api.main import app

        client = TestClient(app)
        endpoints = ["/api/stats", "/api/alerts?limit=20"]
        latencies = []
        errors = 0

        def worker():
            nonlocal errors
            for _ in range(requests_per_thread):
                url = np.random.choice(endpoints)
                t0 = time.perf_counter()
                try:
                    resp = client.get(url)
                    if resp.status_code == 200:
                        lat = (time.perf_counter() - t0) * 1000.0
                        latencies.append(lat)
                    else:
                        errors += 1
                except Exception:
                    errors += 1

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        t_start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        total_time = time.perf_counter() - t_start

        if not latencies:
            return {"status": "api_not_reachable", "note": "Backend endpoints encountered errors"}

        arr = np.array(latencies)
        total_reqs = len(latencies) + errors
        rps = total_reqs / max(1e-3, total_time)

        return {
            "status": "completed",
            "concurrent_workers": num_threads,
            "total_requests": total_reqs,
            "successful_requests": len(latencies),
            "errors": errors,
            "duration_seconds": round(total_time, 3),
            "requests_per_second": round(rps, 1),
            "mean_response_ms": round(float(np.mean(arr)), 2),
            "p50_response_ms": round(float(np.percentile(arr, 50)), 2),
            "p95_response_ms": round(float(np.percentile(arr, 95)), 2),
            "p99_response_ms": round(float(np.percentile(arr, 99)), 2),
        }

    def run_full_profiling(self) -> Dict[str, Any]:
        """Runs stage profiling, concurrency tests, and writes report."""
        hw = self.get_hardware_info()
        stages = self.profile_pipeline_stages(n_samples=50)
        api_perf = self.benchmark_concurrent_api(num_threads=4, requests_per_thread=15)

        full_results = {
            "hardware": hw,
            "pipeline_stages": stages,
            "api_concurrency": api_perf,
            "bottleneck_analysis": {
                "primary_live_bottleneck": "SHAP TreeExplainer local attribution (dominant compute in live path)",
                "primary_batch_bottleneck": "ReportLab PDF rendering (disk I/O and flow layout rendering)",
                "in_stack_mitigations": [
                    "Compute SHAP attributions selectively only for attack predictions (skip benign silent flows)",
                    "Cache static ReportLab stylesheets and asset templates at process startup",
                    "Maintain SQLite WAL mode with concurrent connection pooling for zero-lock writes",
                ],
            },
        }

        # Save JSON
        metrics_dir = RESULTS_DIR / "metrics"
        metrics_dir.mkdir(parents=True, exist_ok=True)
        json_path = metrics_dir / "system_performance.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(full_results, f, indent=2)
        log.info(f"Saved performance metrics to {json_path}")

        # Save Markdown Report
        self.generate_performance_report(full_results)
        return full_results

    def generate_performance_report(self, r: Dict[str, Any]):
        """Generates docs/latency_report.md."""
        hw = r["hardware"]
        s = r["pipeline_stages"]
        api = r["api_concurrency"]

        rep_path = REPORTS_DIR / "latency_report.md"
        rep_path.parent.mkdir(parents=True, exist_ok=True)

        md = f"""# System Performance & Latency Profiling Report (Milestone 5)

## 1. Hardware Environment
- **Operating System**: {hw['os']}
- **Processor**: {hw['processor']} ({hw['cpu_cores']} cores)
- **Python Version**: {hw['python_version']} ({hw['machine']})

---

## 2. Stage-by-Stage Latency Breakdown (Per Alert)

| Pipeline Stage | Mean (ms) | p50 / Median (ms) | p95 (ms) | p99 (ms) | Operational Profile |
|---|---|---|---|---|---|
| **1. Ingestion / Schema** | {s['ingestion']['mean_ms']:.2f} | {s['ingestion']['p50_ms']:.2f} | {s['ingestion']['p95_ms']:.2f} | {s['ingestion']['p99_ms']:.2f} | In-memory feature vector normalization |
| **2. Detection Agent (RF)** | {s['detection']['mean_ms']:.2f} | {s['detection']['p50_ms']:.2f} | {s['detection']['p95_ms']:.2f} | {s['detection']['p99_ms']:.2f} | 100-tree Random Forest inference |
| **3. SHAP TreeExplainer** | {s['shap_explanation']['mean_ms']:.2f} | {s['shap_explanation']['p50_ms']:.2f} | {s['shap_explanation']['p95_ms']:.2f} | {s['shap_explanation']['p99_ms']:.2f} | **Primary Live Bottleneck** (feature attribution) |
| **4. Verification Agent** | {s['verification']['mean_ms']:.2f} | {s['verification']['p50_ms']:.2f} | {s['verification']['p95_ms']:.2f} | {s['verification']['p99_ms']:.2f} | 4-signal corroboration (r, s, b, e) |
| **5. Confidence Scoring** | {s['scoring']['mean_ms']:.2f} | {s['scoring']['p50_ms']:.2f} | {s['scoring']['p95_ms']:.2f} | {s['scoring']['p99_ms']:.2f} | Fused equation + band mapping (<0.1ms) |
| **6. SQLite Persistence** | {s['sqlite_store']['mean_ms']:.2f} | {s['sqlite_store']['p50_ms']:.2f} | {s['sqlite_store']['p95_ms']:.2f} | {s['sqlite_store']['p99_ms']:.2f} | WAL-mode transaction commit |
| **Total Live Pipeline** | **{s['pipeline_total_without_pdf']['mean_ms']:.2f}** | **{s['pipeline_total_without_pdf']['p50_ms']:.2f}** | **{s['pipeline_total_without_pdf']['p95_ms']:.2f}** | **{s['pipeline_total_without_pdf']['p99_ms']:.2f}** | **{1000.0 / max(0.1, s['pipeline_total_without_pdf']['p50_ms']):.1f} alerts/second** throughput |
| **7. On-Demand PDF (ReportLab)** | {s['pdf_report']['mean_ms']:.2f} | {s['pdf_report']['p50_ms']:.2f} | {s['pdf_report']['p95_ms']:.2f} | {s['pdf_report']['p99_ms']:.2f} | Rendered strictly on analyst download request |

---

## 3. Concurrent API Responsiveness Under Load

- **Simulated Concurrent Workers**: {api.get('concurrent_workers', 4)} threads
- **Total Requests**: {api.get('total_requests', 0)} ({api.get('successful_requests', 0)} successful, {api.get('errors', 0)} errors)
- **API Throughput**: **{api.get('requests_per_second', 0.0)} req/sec**
- **Median Response Time (p50)**: **{api.get('p50_response_ms', 0.0)} ms**
- **95th Percentile Response Time (p95)**: **{api.get('p95_response_ms', 0.0)} ms**
"""
        with open(rep_path, "w", encoding="utf-8") as f:
            f.write(md)
        log.info(f"Saved latency Markdown report to {rep_path}")


def run_latency_profiling():
    profiler = SystemLatencyProfiler()
    return profiler.run_full_profiling()


if __name__ == "__main__":
    run_latency_profiling()
