"""Tests for the HauntScan API (task 6, design section 10).

No real network calls or external tools: the scan pipeline is replaced
with a fake ``run_scan`` that just emits ``done``, and validation uses
the sandbox DNS (example.com resolves to a sinkholed address, which
the validator allows — see test_validator.py).
"""

import json
import time

import pytest
from fastapi.testclient import TestClient

from backend.db import database as db
from backend.routers import scans as scans_router
from backend.scan import runner


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


async def _fake_run(scan_id, target, profile, queue, timeout=1800):
    db.update_scan_status(scan_id, "completed")
    await queue.put({"type": "done", "status": "completed"})


@pytest.fixture()
def fake_runner(monkeypatch):
    monkeypatch.setattr(runner, "run_scan", _fake_run)


def _finding_line(template_id, severity):
    return {
        "template-id": template_id,
        "info": {"name": template_id, "severity": severity},
        "matched-at": "https://example.com",
    }


def _seed_completed_scan():
    scan_id = db.create_scan("example.com", "quick")
    for template_id, severity in (
        ("http/low", "low"),
        ("http/critical", "critical"),
    ):
        db.insert_finding(
            {
                "scan_id": scan_id,
                "template_id": template_id,
                "severity": severity,
                "name": template_id,
                "matched_url": "https://example.com",
                "description": "",
            }
        )
    db.update_scan_status(scan_id, "completed")
    return scan_id


def test_create_scan_returns_201(client, fake_runner):
    resp = client.post(
        "/api/scans",
        json={"target": "example.com", "profile": "quick", "authorized": True},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["scan_id"] == 1
    assert body["target"] == "example.com"
    assert body["status"] == "running"
    assert db.get_scan(1) is not None


def test_create_scan_requires_authorization(client, fake_runner):
    resp = client.post(
        "/api/scans",
        json={"target": "example.com", "profile": "quick", "authorized": False},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "Authorization required."


def test_create_scan_rejects_private_target(client, fake_runner):
    for target in ("192.168.1.1", "localhost", "10.0.0.5"):
        resp = client.post(
            "/api/scans",
            json={"target": target, "profile": "quick", "authorized": True},
        )
        assert resp.status_code == 422, target


def test_create_scan_rejects_bad_profile(client, fake_runner):
    resp = client.post(
        "/api/scans",
        json={"target": "example.com", "profile": "turbo", "authorized": True},
    )
    assert resp.status_code == 422


def test_create_scan_conflict_when_running(client, fake_runner, monkeypatch):
    monkeypatch.setattr(runner, "is_scan_running", lambda: True)
    resp = client.post(
        "/api/scans",
        json={"target": "example.com", "profile": "quick", "authorized": True},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"] == "A scan is already in progress."


def test_list_and_get_scan(client):
    scan_id = _seed_completed_scan()
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["finding_counts"] == {
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 1,
        "info": 0,
    }
    resp = client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    # Findings in severity order: critical before low.
    assert [f["severity"] for f in body["findings"]] == ["critical", "low"]


def test_get_missing_scan_404(client):
    assert client.get("/api/scans/999").status_code == 404
    assert client.get("/api/scans/999/stream").status_code == 404
    assert client.get("/api/findings?scan_id=999").status_code == 404


def test_findings_endpoint_severity_order(client):
    scan_id = _seed_completed_scan()
    resp = client.get(f"/api/findings?scan_id={scan_id}")
    assert resp.status_code == 200
    assert [f["severity"] for f in resp.json()] == ["critical", "low"]


def test_sse_replays_completed_scan(client):
    scan_id = _seed_completed_scan()
    resp = client.get(f"/api/scans/{scan_id}/stream")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    events = [
        json.loads(line[6:])
        for line in resp.text.splitlines()
        if line.startswith("data: ")
    ]
    assert [e["type"] for e in events] == ["finding", "finding", "done"]
    assert events[0]["finding"]["severity"] == "critical"
    assert events[-1] == {"type": "done", "status": "completed"}


def test_demo_scan_returns_201(client):
    # No fixture exists yet (task 8 adds it); the endpoint must still
    # create the scan row and return 201.
    resp = client.post("/api/scans/demo")
    assert resp.status_code == 201
    body = resp.json()
    assert body["target"] == "demo.hauntscan.local"
    assert body["profile"] == "quick"
    assert db.get_scan(body["scan_id"]) is not None


def test_live_stream_delivers_done_event(client, fake_runner):
    resp = client.post(
        "/api/scans",
        json={"target": "example.com", "profile": "quick", "authorized": True},
    )
    scan_id = resp.json()["scan_id"]
    # Give the fake background task a moment to emit its done event.
    time.sleep(0.5)
    resp = client.get(f"/api/scans/{scan_id}/stream")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert '"done"' in resp.text
