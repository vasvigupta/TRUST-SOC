"""
Replay Route — Controlled Streaming Simulator & Server-Sent Events (SSE)
========================================================================
Provides streaming replay controls (play, pause, step, speed) and real-time SSE stream.
"""

import time
import json
import logging
from typing import Generator
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from src.ingestion.log_replay import LogReplaySimulator
from src.api.schemas import ReplayControlRequest, ReplayStatusResponse

log = logging.getLogger("TRUST-SOC.api.replay")
router = APIRouter(prefix="/api/replay", tags=["Streaming Replay"])

# Global simulator instance for backend session
_simulator_instance = None


def get_simulator() -> LogReplaySimulator:
    global _simulator_instance
    if _simulator_instance is None:
        log.info("Initializing global LogReplaySimulator for API streaming...")
        _simulator_instance = LogReplaySimulator(records_per_second=5.0, enable_shap=True)
    return _simulator_instance


@router.get("/status", response_model=ReplayStatusResponse, summary="Get current replay simulator state")
def get_replay_status():
    """Returns real-time status of the replay playback simulator."""
    sim = get_simulator()
    return ReplayStatusResponse(
        is_running=sim._is_running,
        is_paused=sim._is_paused,
        rate=sim.rate,
        current_index=sim._current_index,
        total_records=len(sim.df),
        queue_depth=sim.queue.qsize(),
    )


@router.post("/control", summary="Control replay playback state")
def control_replay(payload: ReplayControlRequest):
    """Controls replay state: start, pause, resume, step, or set_rate."""
    sim = get_simulator()
    action = payload.action.lower().strip()

    if action == "start":
        sim.start()
        return {"status": "started", "rate": sim.rate}

    elif action == "pause":
        sim.pause()
        return {"status": "paused"}

    elif action == "resume":
        sim.resume()
        return {"status": "resumed"}

    elif action == "step":
        step_n = payload.n or 1
        alerts = sim.next_n(step_n)
        return {
            "status": "stepped",
            "stepped_count": len(alerts),
            "alerts": [
                {
                    "alert_id": a["alert_id"],
                    "class": a["detection"]["predicted_class"],
                    "decision": a["verification"]["decision"],
                    "confidence": a["scoring"]["composite"],
                    "band": a["scoring"]["band"],
                }
                for a in alerts
            ],
        }

    elif action == "set_rate":
        if payload.rate is None or payload.rate <= 0:
            raise HTTPException(status_code=400, detail="Invalid rate. Must be positive float.")
        sim.set_rate(payload.rate)
        return {"status": "rate_updated", "rate": sim.rate}

    else:
        raise HTTPException(status_code=400, detail=f"Unknown action '{payload.action}'. Allowed: start, pause, resume, step, set_rate.")


@router.get("/stream", summary="Server-Sent Events (SSE) live alert stream")
def stream_alerts():
    """
    Streams newly generated and verified Canonical Alerts in real time via SSE.
    Frontend connects using standard browser EventSource.
    """
    sim = get_simulator()

    def event_generator() -> Generator[str, None, None]:
        # If not already running, start simulator background feed
        if not sim._is_running:
            sim.start()

        log.info("SSE client connected to live alert stream.")
        try:
            while True:
                try:
                    # Non-blocking get with short timeout
                    alert = sim.queue.get(timeout=1.0)
                    data_str = json.dumps(alert, ensure_ascii=False)
                    yield f"data: {data_str}\n\n"
                except Exception:
                    # Heartbeat keepalive comment
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            log.info("SSE client disconnected from live alert stream.")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
