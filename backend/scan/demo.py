"""Demo scan replay for HauntScan (task 6, design section 4.4).

Replays the canned nuclei JSONL fixture through the same SSE event
shapes as a real scan — log lines, finding events, stage events, done —
without invoking any subprocess or network call. The fixture itself is
added in task 8; until then a demo scan fails fast with a clear error
instead of pretending to scan.
"""

from __future__ import annotations

import asyncio
import logging
import os

from backend.db import database as db
from backend.scan.parser import parse_line

logger = logging.getLogger(__name__)

DEMO_TARGET = "demo.hauntscan.local"
DEFAULT_FIXTURE = "tests/fixtures/demo_scan.jsonl"

_demo_lock = asyncio.Lock()


def is_demo_running() -> bool:
    """True while a demo replay holds the single-scan lock."""
    return _demo_lock.locked()


def fixture_path() -> str:
    """Fixture path from env (design section 9) or the default."""
    return os.environ.get("HAUNTSCAN_DEMO_FIXTURE", DEFAULT_FIXTURE)


async def _store_finding(scan_id: int, finding, db_path: str | None) -> int | None:
    if finding.severity not in db.SEVERITIES:
        logger.warning(
            "Skipping demo finding with unusable severity %r (template %s)",
            finding.severity,
            finding.template_id,
        )
        return None
    record = {
        "scan_id": scan_id,
        "template_id": finding.template_id,
        "severity": finding.severity,
        "name": finding.name,
        "matched_url": finding.matched_url,
        "description": finding.description,
        "matcher_name": None,
        "extracted_results": [],
        "curl_command": None,
    }
    return await asyncio.to_thread(db.insert_finding, record, db_path)


async def run_demo(
    scan_id: int,
    queue: asyncio.Queue,
    db_path: str | None = None,
    fixture: str | None = None,
) -> None:
    """Replay the demo fixture onto ``queue`` and mark the scan done.

    Emits ``stage`` events (discovery → probing → scanning) at thirds of
    the fixture, one ``log`` + ``finding`` pair per JSONL line, and a
    final ``done`` event. A missing fixture marks the scan ``failed``.
    """
    path = fixture if fixture is not None else fixture_path()
    if _demo_lock.locked():
        await queue.put(
            {"type": "error", "message": "A scan is already in progress."}
        )
        return
    await _demo_lock.acquire()
    try:
        try:
            with open(path, encoding="utf-8") as fh:
                lines = [line.rstrip("\n") for line in fh if line.strip()]
        except OSError as exc:
            message = f"Demo fixture not found: {path} ({exc})"
            await asyncio.to_thread(
                db.update_scan_status, scan_id, "failed",
                error_message=message, db_path=db_path,
            )
            await queue.put({"type": "error", "message": message})
            return

        stages = ("discovery", "probing", "scanning")
        total = max(len(lines), 1)
        await queue.put({"type": "stage", "stage": "discovery"})
        for i, line in enumerate(lines):
            stage = stages[min(i * len(stages) // total, len(stages) - 1)]
            if i == 0 or (i * len(stages) // total) != (
                (i - 1) * len(stages) // total
            ):
                await queue.put({"type": "stage", "stage": stage})
            await queue.put({"type": "log", "message": line})
            finding = parse_line(line)
            if finding is None:
                continue
            finding_id = await _store_finding(scan_id, finding, db_path)
            if finding_id is None:
                continue
            await queue.put(
                {
                    "type": "finding",
                    "finding": {
                        "finding_id": finding_id,
                        "scan_id": scan_id,
                        "template_id": finding.template_id,
                        "severity": finding.severity,
                        "name": finding.name,
                        "matched_url": finding.matched_url,
                        "description": finding.description,
                    },
                }
            )
            await asyncio.sleep(0.05)
        await asyncio.to_thread(
            db.update_scan_status, scan_id, "completed", db_path=db_path
        )
        await queue.put({"type": "done", "status": "completed"})
    finally:
        _demo_lock.release()
