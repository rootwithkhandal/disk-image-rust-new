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

import sys
from pathlib import Path

# Ensure backend/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


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


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "3.0.0"
    }


# ── Direct run ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=True)
