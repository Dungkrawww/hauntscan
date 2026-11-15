"""Tests for backend.scan.runner (task 5).

No real network calls or external tools are involved: the subprocess is
either mocked with a fake process or a real local ``python -c`` command
that prints canned nuclei JSONL lines (test hook ``command=``).
"""

import asyncio
import json
import sys
from unittest import mock

import pytest

from backend.db import database as db
from backend.scan import runner


@pytest.fixture(autouse=True)
def _memory_db():
    db.init_db(":memory:")
    yield
    db.close(":memory:")


def _finding_line(**overrides):
    base = {
        "template-id": "http/missing-security-headers",
        "info": {
            "name": "Missing Security Headers",
            "severity": "high",
            "description": "Checks for missing headers.",
            "tags": ["misc"],
        },
        "matched-at": "https://example.com",
    }
    base.update(overrides)
    return json.dumps(base)


def _drain(queue: asyncio.Queue) -> list:
    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    return events


def _run(coro):
    """Run an async helper without needing pytest-asyncio."""
    return asyncio.run(coro)


class _FakeStdout:
    def __init__(self, lines, delay=0.0):
        self._lines = [line.encode() + b"\n" for line in lines]
        self._delay = delay

    async def __aiter__(self):
        for line in self._lines:
            if self._delay:
                await asyncio.sleep(self._delay)
            yield line


class _FakeProcess:
    def __init__(self, lines, returncode=0, delay=0.0):
        self.pid = 999999  # no such process: killpg must not raise
        self.stdout = _FakeStdout(lines, delay=delay)
        self.returncode = returncode
        self.killed = False

    def kill(self):
        self.killed = True

    async def wait(self):
        return self.returncode


def test_build_command_quick_and_full():
    assert runner.build_command("example.com", "quick") == [
        "nf",
        "-u",
        "example.com",
    ]
    assert runner.build_command("example.com", "full") == [
        "nf",
        "-u",
        "example.com",
        "-t",
        "fuzzing-templates",
    ]


def test_build_command_rejects_unknown_profile_and_forbidden_tokens():
    with pytest.raises(ValueError):
        runner.build_command("example.com", "turbo")
    for command in (
        runner.build_command("example.com", "quick"),
        runner.build_command("example.com", "full"),
    ):
        assert "--validate" not in command
        assert "sqlmap" not in command
        assert "dalfox" not in command


def test_mocked_run_stores_finding_and_completes():
    scan_id = db.create_scan("example.com", "quick")
    queue: asyncio.Queue = asyncio.Queue()
    fake = _FakeProcess([_finding_line(), "nuclei scan finished"])
    with mock.patch(
        "asyncio.create_subprocess_exec",
        new=mock.AsyncMock(return_value=fake),
    ):
        _run(runner.run_scan(scan_id, "example.com", "quick", queue))

    events = _drain(queue)
    assert [e["type"] for e in events] == ["log", "finding", "log", "done"]
    assert events[1]["finding"]["template_id"] == "http/missing-security-headers"
    assert events[1]["finding"]["severity"] == "high"
    assert events[1]["finding"]["finding_id"] == 1
    assert events[-1] == {"type": "done", "status": "completed"}
    assert db.get_scan(scan_id)["status"] == "completed"
    findings = db.get_findings(scan_id)
    assert len(findings) == 1
    assert findings[0]["matched_url"] == "https://example.com"


def test_unknown_severity_line_is_skipped_not_stored():
    scan_id = db.create_scan("example.com", "quick")
    queue: asyncio.Queue = asyncio.Queue()
    weird = _finding_line(info={"name": "X", "severity": "weird"})
    fake = _FakeProcess([weird, "not json at all"])
    with mock.patch(
        "asyncio.create_subprocess_exec",
        new=mock.AsyncMock(return_value=fake),
    ):
        _run(runner.run_scan(scan_id, "example.com", "quick", queue))

    assert db.get_findings(scan_id) == []
    assert db.get_scan(scan_id)["status"] == "completed"
    events = _drain(queue)
    assert events[-1] == {"type": "done", "status": "completed"}
    assert not any(e["type"] == "finding" for e in events)


def test_nonzero_exit_marks_scan_failed():
    scan_id = db.create_scan("example.com", "quick")
    queue: asyncio.Queue = asyncio.Queue()
    fake = _FakeProcess(["something went wrong"], returncode=2)
    with mock.patch(
        "asyncio.create_subprocess_exec",
        new=mock.AsyncMock(return_value=fake),
    ):
        _run(runner.run_scan(scan_id, "example.com", "quick", queue))

    scan = db.get_scan(scan_id)
    assert scan["status"] == "failed"
    assert "code 2" in (scan["error_message"] or "")
    events = _drain(queue)
    assert events[-1]["type"] == "error"


def test_second_concurrent_scan_is_rejected():
    first_id = db.create_scan("a.example.com", "quick")
    second_id = db.create_scan("b.example.com", "quick")
    first_queue: asyncio.Queue = asyncio.Queue()
    second_queue: asyncio.Queue = asyncio.Queue()
    fake = _FakeProcess([_finding_line()], delay=0.2)
    create = mock.AsyncMock(return_value=fake)
    async def _both():
        await asyncio.gather(
            runner.run_scan(first_id, "a.example.com", "quick", first_queue),
            runner.run_scan(second_id, "b.example.com", "quick", second_queue),
        )

    with mock.patch("asyncio.create_subprocess_exec", new=create):
        _run(_both())

    assert create.await_count == 1
    assert runner.is_scan_running() is False
    second_events = _drain(second_queue)
    assert second_events == [
        {"type": "error", "message": "A scan is already in progress."}
    ]
    assert db.get_scan(first_id)["status"] == "completed"


def test_timeout_kills_process_group_and_marks_failed():
    scan_id = db.create_scan("example.com", "quick")
    queue: asyncio.Queue = asyncio.Queue()

    class _HangingStdout:
        async def __aiter__(self):
            await asyncio.sleep(3600)
            yield b"never\n"

    fake = _FakeProcess([])
    fake.stdout = _HangingStdout()
    with mock.patch(
        "asyncio.create_subprocess_exec",
        new=mock.AsyncMock(return_value=fake),
    ):
        _run(
            runner.run_scan(
                scan_id, "example.com", "quick", queue, timeout=0.05
            )
        )

    scan = db.get_scan(scan_id)
    assert scan["status"] == "failed"
    assert "timed out" in (scan["error_message"] or "")
    events = _drain(queue)
    assert events[-1] == {
        "type": "error",
        "message": "Scan timed out after 0.05s",
    }


def test_real_subprocess_end_to_end():
    """Real asyncio subprocess (local python, no network): prints one
    JSONL finding and one plain log line; runner must store the finding
    and mark the scan completed."""
    scan_id = db.create_scan("example.com", "quick")
    queue: asyncio.Queue = asyncio.Queue()
    script = (
        "import json, sys;"
        "print(json.dumps({'template-id': 'http/test',"
        " 'info': {'name': 'Test', 'severity': 'medium'},"
        " 'matched-at': 'https://example.com'}));"
        "print('demo scan line', flush=True)"
    )
    _run(
        runner.run_scan(
            scan_id,
            "example.com",
            "quick",
            queue,
            command=[sys.executable, "-c", script],
        )
    )

    assert db.get_scan(scan_id)["status"] == "completed"
    findings = db.get_findings(scan_id)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    events = _drain(queue)
    assert events[-1] == {"type": "done", "status": "completed"}
    assert any(e["type"] == "finding" for e in events)
