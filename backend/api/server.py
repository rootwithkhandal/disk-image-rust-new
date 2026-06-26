"""
ForgeLens API Server
====================
Lightweight FastAPI server that exposes backend functionality to the frontend.

Usage:
    uvicorn backend.api.server:app --reload --port 8000
    # or
    python -m backend.api.server
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Ensure backend/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import devices
from api.routes import v3 as v3_routes
from core.v3.streaming import broker

app = FastAPI(
    title="ForgeLens API",
    version="3.0.0",
    description="ForgeLens DFIR Platform — Battlefield Edition",
)

# CORS — allow local development clients and API testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:1420", "http://127.0.0.1:1420", "tauri://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(devices.router, prefix="/api")
app.include_router(v3_routes.router)  # All /api/v3/* routes


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "stream_channels": broker.channels(),
    }


# ── Startup: wire streaming loop ──────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    broker.set_loop(asyncio.get_running_loop())
    broker.publish("global", "server_started", {"version": "3.0.0"})


# ── Direct run ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=True)
