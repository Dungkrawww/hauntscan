"""Tests for the HauntScan demo mode (task 8, design section 4.4).

The demo replays the canned fixture at tests/fixtures/demo_scan.jsonl
through the same SSE event shapes as a real scan — no subprocess, no
network. The fixture path is the one requirements US-5.2 and design
section 4.4 name; tasks.md's one-liner says backend/fixtures/, but the
spec and the existing demo.py default agree on tests/fixtures/.
"""

import asyncio
from pathlib import Path

from backend.db import database as db
from backend.scan import demo as demo_module
from backend.scan.parser import parse_line

FIXTURE = Path(__file__).parent / "fixtures" / "demo_scan.jsonl"

EXPECTED_COUNTS = {"critical": 1, "high": 2, "medium": 2, "low": 1, "info": 2}


def _lines():
    return [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


def _drain(queue: asyncio.Queue) -> list:
    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    return events


def test_fixture_exists_and_parses():
    assert FIXTURE.is_file(), f"demo fixture missing: {FIXTURE}"
    findings = [parse_line(line) for line in _lines()]
    assert len(findings) == 8
    assert all(f is not None for f in findings)
    counts = {}
    for finding in findings:
        assert finding.severity in db.SEVERITIES
        assert finding.matched_url.startswith("https://demo.hauntscan.local/")
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    assert counts == EXPECTED_COUNTS


def test_run_demo_replays_all_events(tmp_path):
    db_path = str(tmp_path / "demo.db")
    db.init_db(db_path)
    try:
        scan_id = db.create_scan("demo.hauntscan.local", "quick", db_path)
        queue: asyncio.Queue = asyncio.Queue()
        asyncio.run(
            demo_module.run_demo(scan_id, queue, db_path=db_path, fixture=str(FIXTURE))
        )
        events = _drain(queue)
        types = [event["type"] for event in events]
        assert "done" in types
        assert types[-1] == "done"
        assert events[-1]["status"] == "completed"
        stages = {event["stage"] for event in events if event["type"] == "stage"}
        assert stages == {"discovery", "probing", "scanning"}
        finding_events = [event for event in events if event["type"] == "finding"]
        assert len(finding_events) == 8
        assert not [event for event in events if event["type"] == "error"]
        scan = db.get_scan_with_findings(scan_id, db_path)
        assert scan["status"] == "completed"
        stored = scan["findings"]
        assert len(stored) == 8
        stored_counts = {}
        for row in stored:
            stored_counts[row["severity"]] = stored_counts.get(row["severity"], 0) + 1
        assert stored_counts == EXPECTED_COUNTS
    finally:
        db.close(db_path)


def test_run_demo_missing_fixture_fails_fast(tmp_path):
    db_path = str(tmp_path / "demo.db")
    db.init_db(db_path)
    try:
        scan_id = db.create_scan("demo.hauntscan.local", "quick", db_path)
        queue: asyncio.Queue = asyncio.Queue()
        asyncio.run(
            demo_module.run_demo(
                scan_id, queue, db_path=db_path, fixture="/nonexistent/demo.jsonl"
            )
        )
        events = _drain(queue)
        errors = [event for event in events if event["type"] == "error"]
        assert len(errors) == 1
        assert "Demo fixture not found" in errors[0]["message"]
        assert "done" not in [event["type"] for event in events]
        scan = db.get_scan_with_findings(scan_id, db_path)
        assert scan["status"] == "failed"
    finally:
        db.close(db_path)
