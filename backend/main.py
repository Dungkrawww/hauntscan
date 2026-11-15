"""HauntScan entry point (task 6, design section 2.1).

Single-process FastAPI app: API routers + static frontend at ``/``.
CORS is localhost-only (single-user local app). The SQLite store is
initialised on startup; the DB path comes from ``HAUNTSCAN_DB_PATH``
(design section 9, default ``hauntscan.db``).
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.db import database as db
from backend.routers import findings, scans

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(title="HauntScan")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    db.init_db(os.environ.get("HAUNTSCAN_DB_PATH"))


app.include_router(scans.router)
app.include_router(findings.router)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


# Static frontend last, so /api/* routes win. Serves index.html for /
# once task 7 creates it; until then / returns 404.
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
