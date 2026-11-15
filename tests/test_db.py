"""Tests for backend.db.database (task 4).

All tests run against an in-memory SQLite database; no files, network or
external tools are involved.
"""

import pytest

from backend.db import database as db


@pytest.fixture(autouse=True)
def _memory_db():
    db.init_db(":memory:")
    yield
    db.close(":memory:")


def _finding(scan_id, severity="high", template_id="http/test"):
    return {
        "scan_id": scan_id,
        "template_id": template_id,
        "severity": severity,
        "name": "Test finding",
        "matched_url": "https://example.com",
        "description": "desc",
        "matcher_name": "word",
        "extracted_results": ["evidence"],
        "curl_command": "curl https://example.com",
    }


def test_create_and_get_scan():
    scan_id = db.create_scan("example.com", "quick")
    scan = db.get_scan(scan_id)
    assert scan is not None
    assert scan["target"] == "example.com"
    assert scan["profile"] == "quick"
    assert scan["status"] == "running"
    assert scan["created_at"]
    assert scan["ended_at"] is None
    assert scan["duration_seconds"] is None
    assert scan["finding_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def test_create_scan_rejects_bad_profile_and_empty_target():
    with pytest.raises(ValueError):
        db.create_scan("example.com", "turbo")
    with pytest.raises(ValueError):
        db.create_scan("   ", "quick")


def test_get_missing_scan_returns_none():
    assert db.get_scan(9999) is None


def test_update_status_stamps_ended_at_and_error():
    scan_id = db.create_scan("example.com", "full")
    db.update_scan_status(scan_id, "failed", error_message="boom")
    scan = db.get_scan(scan_id)
    assert scan["status"] == "failed"
    assert scan["error_message"] == "boom"
    assert scan["ended_at"] is not None
    assert scan["duration_seconds"] is not None
    assert scan["duration_seconds"] >= 0


def test_update_missing_scan_raises():
    with pytest.raises(KeyError):
        db.update_scan_status(9999, "completed")


def test_insert_and_get_findings_in_severity_order():
    scan_id = db.create_scan("example.com", "quick")
    for severity in ("info", "critical", "low", "high", "medium"):
        db.insert_finding(_finding(scan_id, severity, f"t-{severity}"))
    findings = db.get_findings(scan_id)
    assert [f["severity"] for f in findings] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]
    assert findings[0]["template_id"] == "t-critical"
    assert findings[0]["extracted_results"] == ["evidence"]
    assert findings[0]["curl_command"] == "curl https://example.com"


def test_finding_counts_aggregated_in_scan_and_list():
    first = db.create_scan("a.example.com", "quick")
    second = db.create_scan("b.example.com", "full")
    db.insert_finding(_finding(first, "high", "t-1"))
    db.insert_finding(_finding(first, "high", "t-2"))
    db.insert_finding(_finding(first, "info", "t-3"))
    assert db.get_scan(first)["finding_counts"]["high"] == 2
    assert db.get_scan(first)["finding_counts"]["info"] == 1
    listed = db.list_scans()
    assert [s["scan_id"] for s in listed] == [second, first]  # newest first
    assert listed[1]["finding_counts"]["high"] == 2


def test_get_scan_with_findings():
    scan_id = db.create_scan("example.com", "quick")
    db.insert_finding(_finding(scan_id, "medium"))
    detail = db.get_scan_with_findings(scan_id)
    assert detail is not None
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["severity"] == "medium"
    assert db.get_scan_with_findings(9999) is None


def test_insert_finding_rejects_unknown_severity():
    scan_id = db.create_scan("example.com", "quick")
    with pytest.raises(ValueError):
        db.insert_finding(_finding(scan_id, "unknown"))


def test_insert_finding_rejects_missing_scan():
    with pytest.raises(Exception):
        db.insert_finding(_finding(9999, "high"))


def test_init_db_is_idempotent_and_file_db_uses_wal(tmp_path):
    path = str(tmp_path / "test.db")
    db.init_db(path)
    scan_id = db.create_scan("example.com", "quick", db_path=path)
    db.init_db(path)  # second init must not wipe the row
    assert db.get_scan(scan_id, db_path=path) is not None
    import sqlite3

    mode = sqlite3.connect(path).execute("PRAGMA journal_mode").fetchone()[0]
    assert mode == "wal"
    db.close(path)
