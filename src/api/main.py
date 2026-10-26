"""
TRUST-SOC FastAPI Backend Application (Milestone 4)
===================================================
Serves the complete TRUST-SOC REST API, SSE streaming feed, ReportLab PDF evidence reports,
and hosts the React.js + Chart.js SOC dashboard.
"""

import sys
import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from src.config.config import CORS_ORIGINS, API_HOST, API_PORT, ROOT_DIR
from src.database.db import init_db
from src.api.routes import health, stats, alerts, replay, detection

log = logging.getLogger("TRUST-SOC.api")

app = FastAPI(
    title="TRUST-SOC SOC API",
    description=(
        "Trust-Aware, Verification-Driven Detection Pipeline for Security Operations Centers.\n\n"
        "Features independent multi-signal verification (rule, statistical, behavioural, explanation), "
        "composite confidence scoring, ReportLab PDF evidence generation, and real-time SSE streaming."
    ),
    version="1.0.0",
    contact={"name": "TRUST-SOC Engineering Team (BVCOE New Delhi)"},
)

# ── CORS Middleware ────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Startup Lifecycle ──────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    init_db()
    log.info("=" * 60)
    log.info("TRUST-SOC FastAPI Backend Service Started")
    log.info(f"API Docs (Swagger UI): http://{API_HOST}:{API_PORT}/docs")
    log.info(f"API ReDoc:            http://{API_HOST}:{API_PORT}/redoc")
    log.info("=" * 60)


# ── Include Routers ────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(stats.router)
app.include_router(alerts.router)
app.include_router(replay.router)
app.include_router(detection.router)

# ── Mount React Frontend ───────────────────────────────────────────
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"
if FRONTEND_DIST.exists():
    # Mount assets directory
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_react_app(full_path: str):
        # Serve exact file if it exists, otherwise fallback to index.html for React SPA router
        requested_file = FRONTEND_DIST / full_path
        if full_path and requested_file.is_file():
            return FileResponse(str(requested_file))
        return FileResponse(str(FRONTEND_DIST / "index.html"))
else:
    @app.get("/", include_in_schema=False)
    def root_info():
        return {
            "message": "TRUST-SOC FastAPI Backend Service is running.",
            "frontend_status": "React frontend not built yet. Run 'npm run build' in frontend/ directory.",
            "api_docs": f"http://localhost:{API_PORT}/docs",
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.api.main:app", host=API_HOST, port=API_PORT, reload=True)
