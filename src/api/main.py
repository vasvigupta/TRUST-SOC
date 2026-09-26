"""
TRUST-SOC FastAPI Application
===============================
Entry point for the backend API server.

Endpoints:
  GET  /                           Health check
  POST /detect                     Run detection on one flow
  GET  /alerts                     List alerts (paginated)
  GET  /alerts/summary             Per-class counts
  GET  /alerts/{alert_id}          Single alert
  DELETE /alerts                   Clear all alerts (dev)
  GET  /metrics                    Baseline detection metrics
  GET  /replay?n=20                Trigger log replay
  GET  /reports/{alert_id}/pdf     Download PDF report
  GET  /reports/shap-plot          SHAP bar chart PNG
  GET  /reports/confusion-matrix   Confusion matrix PNG
  GET  /docs                       Swagger UI (auto-generated)
  GET  /redoc                      ReDoc UI (auto-generated)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config.config import CORS_ORIGINS, API_HOST, API_PORT
from src.database.db import init_db
from src.api.routes import detection, alerts, metrics, reports

# ── App ───────────────────────────────────────────────────────────
app = FastAPI(
    title       = "TRUST-SOC API",
    description = (
        "Trust-Aware, Verification-Driven Detection Pipeline for SOC.\n\n"
        "**BTech CSE Micro-Project — Detection Agent Prototype**\n\n"
        "> Verification Agent is a planned Phase 2 component."
    ),
    version     = "0.1.0",
    contact     = {"name": "TRUST-SOC Team"},
    license_info= {"name": "MIT"},
)

# ── CORS (allow React dev server) ─────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins     = CORS_ORIGINS,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Startup ───────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    init_db()
    print("[TRUST-SOC] FastAPI server started.")
    print(f"[TRUST-SOC] Swagger UI -> http://localhost:{API_PORT}/docs")
    print(f"[TRUST-SOC] ReDoc      -> http://localhost:{API_PORT}/redoc")


# ── Routers ───────────────────────────────────────────────────────
app.include_router(detection.router)
app.include_router(alerts.router)
app.include_router(metrics.router)
app.include_router(reports.router)

# ── Health check ──────────────────────────────────────────────────
@app.get("/", tags=["Health"], summary="API health check")
def root():
    return {
        "service": "TRUST-SOC API",
        "version": "0.1.0",
        "status":  "running",
        "docs":    f"http://localhost:{API_PORT}/docs",
    }


# ── Dev runner ────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main:app",
        host    = API_HOST,
        port    = API_PORT,
        reload  = True,
        log_level = "info",
    )
