"""Tests for the HauntScan findings API (task 9, design section 2.2).

GET /api/findings?scan_id={id} returns the scan's findings ordered by
severity rank (critical first). 404 when the scan does not exist.
No real network calls or external tools.
"""

import pytest
from fastapi.testclient import TestClient

from backend.db import database as db
from backend.routers import scans as scans_router


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("HAUNTSCAN_DB_PATH", db_path)
    db.init_db(db_path)
    scans_router._queues.clear()
    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client
    scans_router._queues.clear()
    db.close(db_path)


def _seed_scan_with_findings(severities):
    scan_id = db.create_scan("example.com", "quick")
    for i, severity in enumerate(severities):
        db.insert_finding(
            {
                "scan_id": scan_id,
                "template_id": f"http/test-{severity}-{i}",
                "severity": severity,
                "name": f"Test {severity}",
                "matched_url": "https://example.com",
                "description": "",
            }
        )
    db.update_scan_status(scan_id, "completed")
    return scan_id


def test_findings_ordered_by_severity(client):
    scan_id = _seed_scan_with_findings(
        ["info", "critical", "low", "high", "medium", "info", "critical"]
    )
    resp = client.get("/api/findings", params={"scan_id": scan_id})
    assert resp.status_code == 200
    severities = [row["severity"] for row in resp.json()]
    assert severities == [
        "critical",
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "info",
    ]


def test_findings_fields_present(client):
    scan_id = _seed_scan_with_findings(["high"])
    row = client.get("/api/findings", params={"scan_id": scan_id}).json()[0]
    assert row["template_id"] == "http/test-high-0"
    assert row["severity"] == "high"
    assert row["matched_url"] == "https://example.com"
    assert isinstance(row["extracted_results"], list)


def test_findings_empty_scan_returns_empty_list(client):
    scan_id = db.create_scan("example.com", "quick")
    resp = client.get("/api/findings", params={"scan_id": scan_id})
    assert resp.status_code == 200
    assert resp.json() == []


def test_findings_unknown_scan_404(client):
    resp = client.get("/api/findings", params={"scan_id": 999})
    assert resp.status_code == 404
