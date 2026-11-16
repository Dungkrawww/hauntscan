"""Scan API routes for HauntScan (task 6, design sections 2.2 and 6).

Endpoints:
- POST /api/scans          start a real (NucleiFuzzer) scan
- POST /api/scans/demo     start a demo replay (no subprocess/network)
- GET  /api/scans          scan history, newest first
- GET  /api/scans/{id}     one scan + its findings
- GET  /api/scans/{id}/stream  SSE log stream (live or replay)

Error contract (design section 8): unauthorized -> 422, invalid or
private target -> 422, scan already running -> 409, unknown id -> 404.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.db import database as db
from backend.scan import demo as demo_runner
from backend.scan import runner
from backend.scan.validator import InvalidTarget, validate_target

router = APIRouter(prefix="/api/scans", tags=["scans"])

# scan_id -> live event queue (design section 6). Created before the
# background task starts; removed after the terminal event is consumed.
_queues: dict[int, asyncio.Queue] = {}



class ScanRequest(BaseModel):
    target: str
    profile: str = Field(default="quick", pattern="^(quick|full)$")
    authorized: bool = False


def _scan_running() -> bool:
    return runner.is_scan_running() or demo_runner.is_demo_running()


def _timeout() -> float:
    try:
        return float(os.environ.get("HAUNTSCAN_SCAN_TIMEOUT", "1800"))
    except ValueError:
        return 1800.0


def _demo_only() -> bool:
    """True when the public demo deployment must refuse real scans.

    Env HAUNTSCAN_DEMO_ONLY=1 (also "true"/"yes"/"on") disables
    POST /api/scans so a public instance can never trigger the
    NucleiFuzzer toolchain against arbitrary targets. The demo
    endpoint stays open.
    """
    return os.environ.get("HAUNTSCAN_DEMO_ONLY", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


async def _get_scan_or_404(scan_id: int) -> dict:
    scan = await asyncio.to_thread(db.get_scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _start_scan(
    background: BackgroundTasks, scan_id: int, target: str, profile: str
) -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue()
    _queues[scan_id] = queue
    background.add_task(
        runner.run_scan,
        scan_id,
        target,
        profile,
        queue,
        _timeout(),
    )
    return queue


@router.post("", status_code=201)
async def create_scan(
    body: ScanRequest, background: BackgroundTasks
) -> dict:
    """Validate, create the scan row, and start the pipeline."""
    if _demo_only():
        raise HTTPException(
            status_code=403,
            detail="Real scans are disabled in demo mode.",
        )
    if not body.authorized:
        raise HTTPException(
            status_code=422, detail="Authorization required."
        )
    try:
        target = validate_target(body.target)
    except InvalidTarget as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if _scan_running():
        raise HTTPException(
            status_code=409, detail="A scan is already in progress."
        )
    scan_id = await asyncio.to_thread(
        db.create_scan, target, body.profile
    )
    _start_scan(background, scan_id, target, body.profile)
    scan = await asyncio.to_thread(db.get_scan, scan_id)
    return scan


@router.post("/demo", status_code=201)
async def create_demo_scan(background: BackgroundTasks) -> dict:
    """Create a demo scan row and replay the fixture through SSE."""
    if _scan_running():
        raise HTTPException(
            status_code=409, detail="A scan is already in progress."
        )
    scan_id = await asyncio.to_thread(
        db.create_scan, demo_runner.DEMO_TARGET, "quick"
    )
    queue: asyncio.Queue = asyncio.Queue()
    _queues[scan_id] = queue
    background.add_task(demo_runner.run_demo, scan_id, queue)
    scan = await asyncio.to_thread(db.get_scan, scan_id)
    return scan


@router.get("")
async def list_scans() -> list[dict]:
    return await asyncio.to_thread(db.list_scans)


@router.get("/{scan_id}")
async def get_scan(scan_id: int) -> dict:
    scan = await asyncio.to_thread(db.get_scan_with_findings, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


async def _event_stream(scan_id: int, scan: dict):
    """Yield SSE events: replay a finished scan, or subscribe live."""
    if scan["status"] in ("completed", "failed"):
        findings = await asyncio.to_thread(db.get_findings, scan_id)
        for finding in findings:
            yield f"data: {json.dumps({'type': 'finding', 'finding': finding})}\n\n"
        if scan["status"] == "completed":
            yield f"data: {json.dumps({'type': 'done', 'status': 'completed'})}\n\n"
        else:
            yield (
                f"data: {json.dumps({'type': 'error', 'message': scan.get('error_message') or 'Scan failed'})}\n\n"
            )
        return

    queue = _queues.get(scan_id)
    if queue is None:
        # Scan is marked running but its queue is gone (e.g. app
        # restarted): report what the DB knows instead of hanging.
        yield f"data: {json.dumps({'type': 'log', 'message': 'Scan is running; live log unavailable after restart.'})}\n\n"
        return
    try:
        while True:
            event = await queue.get()
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") in ("done", "error"):
                _queues.pop(scan_id, None)
                break
    except asyncio.CancelledError:
        # Client disconnected: leave the queue registered so another
        # client can pick up the remaining events; never kill the scan.
        return


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: int) -> StreamingResponse:
    scan = await _get_scan_or_404(scan_id)
    return StreamingResponse(
        _event_stream(scan_id, scan), media_type="text/event-stream"
    )
