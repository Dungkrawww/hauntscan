"""Findings API routes for HauntScan (task 6, design section 2.2).

GET /api/findings?scan_id={id} — findings for one scan, ordered by
severity rank (critical first). 404 when the scan does not exist.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException

from backend.db import database as db

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("")
async def list_findings(scan_id: int) -> list[dict]:
    scan = await asyncio.to_thread(db.get_scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return await asyncio.to_thread(db.get_findings, scan_id)
