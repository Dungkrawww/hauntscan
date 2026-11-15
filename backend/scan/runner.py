"""Scan runner for HauntScan (task 5).

Runs the NucleiFuzzer pipeline as an ``asyncio`` background task and
streams events onto an ``asyncio.Queue`` for the SSE layer (design
sections 2.3, 4.2 and 6):

- ``{"type": "log", "message": line}`` for every subprocess stdout line
- ``{"type": "finding", "finding": {...}}`` for each parsed nuclei JSONL
  line that was stored in SQLite
- ``{"type": "done", "status": "completed"}`` on success
- ``{"type": "error", "message": ...}`` on failure / timeout

Safety rules (from the spec and ``.kiro/steering/safety.md``):
- the command never contains ``--validate``, ``sqlmap`` or ``dalfox``
- at most one scan runs at a time (module-level ``asyncio.Lock``)
- hard timeout (default 1800 s); on expiry the whole process group is
  SIGKILLed

Notes on where the implementation differs from design section 4:
- Design section 4.3 describes ``parser.parse_finding(line, scan_id)``
  that inserts into SQLite. The parser as implemented (task 3) is
  ``parse_line(line) -> Finding`` with no DB side effect and no
  ``matcher_name`` / ``extracted_results`` / ``curl_command`` fields, so
  the runner does the insert itself, via ``asyncio.to_thread`` because
  the SQLite wrapper is synchronous.
- A finding whose severity is ``"unknown"`` cannot be stored: the
  ``findings`` table CHECK-constrains severity to the five real values
  and ``insert_finding`` raises for it. Such lines are logged and
  skipped (no ``finding`` event, no DB row) instead of storing a wrong
  severity.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal

from backend.db import database as db
from backend.scan.parser import parse_line

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 1800

# Quick: default NucleiFuzzer templates. Full: extended fuzzing templates.
_PROFILE_ARGS: dict[str, list[str]] = {
    "quick": ["nf", "-u"],
    "full": ["nf", "-u"],
}
_PROFILE_EXTRA_ARGS: dict[str, list[str]] = {
    "quick": [],
    "full": ["-t", "fuzzing-templates"],
}

# Banned tokens: active-exploitation helpers that must never appear in a
# scan command, even if a caller asks for them.
_FORBIDDEN_TOKENS = ("--validate", "sqlmap", "dalfox")

_scan_lock = asyncio.Lock()


def is_scan_running() -> bool:
    """True while a scan holds the single-scan lock."""
    return _scan_lock.locked()


def build_command(target: str, profile: str) -> list[str]:
    """Build the NucleiFuzzer command for ``profile``.

    Raises ``ValueError`` for an unknown profile. The returned command
    never contains ``--validate``, ``sqlmap`` or ``dalfox``.
    """
    if profile not in _PROFILE_ARGS:
        raise ValueError(f"profile must be one of {sorted(_PROFILE_ARGS)}, got {profile!r}")
    command = [*_PROFILE_ARGS[profile], target, *_PROFILE_EXTRA_ARGS[profile]]
    for token in command:
        if token in _FORBIDDEN_TOKENS:
            raise ValueError(f"forbidden token in scan command: {token!r}")
    return command


async def _store_finding(scan_id: int, finding, db_path: str | None) -> int | None:
    """Insert one parsed finding; return its id, or None if skipped."""
    if finding.severity not in db.SEVERITIES:
        logger.warning(
            "Skipping finding with unusable severity %r (template %s)",
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


async def _drain_stdout(
    scan_id: int,
    proc: asyncio.subprocess.Process,
    queue: asyncio.Queue,
    db_path: str | None,
) -> None:
    """Read subprocess stdout line by line; log lines and findings."""
    assert proc.stdout is not None
    async for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").rstrip("\n")
        if not line.strip():
            continue
        await queue.put({"type": "log", "message": line})
        finding = parse_line(line)
        if finding is None:
            continue
        finding_id = await _store_finding(scan_id, finding, db_path)
        if finding_id is None:
            await queue.put(
                {
                    "type": "log",
                    "message": f"[runner] skipped finding with severity "
                    f"{finding.severity!r} (template {finding.template_id})",
                }
            )
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


async def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """SIGKILL the subprocess' whole process group; never raise."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError) as exc:
        logger.warning("Could not kill scan process group %s: %s", proc.pid, exc)
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
    try:
        await proc.wait()
    except Exception:  # noqa: BLE001 - best effort cleanup only
        pass


async def run_scan(
    scan_id: int,
    target: str,
    profile: str,
    queue: asyncio.Queue,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    db_path: str | None = None,
    command: list[str] | None = None,
) -> None:
    """Run one scan and stream its events onto ``queue``.

    ``command`` overrides the built NucleiFuzzer command; it exists so
    tests can run a real subprocess without network or external tools.
    Production callers must leave it unset.
    """
    if _scan_lock.locked():
        message = "A scan is already in progress."
        await queue.put({"type": "error", "message": message})
        return
    try:
        cmd = list(command) if command is not None else build_command(target, profile)
    except ValueError as exc:
        await asyncio.to_thread(
            db.update_scan_status, scan_id, "failed", error_message=str(exc), db_path=db_path
        )
        await queue.put({"type": "error", "message": str(exc)})
        return

    await _scan_lock.acquire()
    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,  # own process group, for killpg on timeout
        )
        try:
            await asyncio.wait_for(
                _drain_stdout(scan_id, proc, queue, db_path), timeout=timeout
            )
        except asyncio.TimeoutError:
            message = f"Scan timed out after {timeout:g}s"
            await _kill_process_group(proc)
            await asyncio.to_thread(
                db.update_scan_status, scan_id, "failed", error_message=message, db_path=db_path
            )
            await queue.put({"type": "error", "message": message})
            return
        returncode = await proc.wait()
        if returncode != 0:
            message = f"Scan exited with code {returncode}"
            await asyncio.to_thread(
                db.update_scan_status, scan_id, "failed", error_message=message, db_path=db_path
            )
            await queue.put({"type": "error", "message": message})
            return
        await asyncio.to_thread(
            db.update_scan_status, scan_id, "completed", db_path=db_path
        )
        await queue.put({"type": "done", "status": "completed"})
    except Exception as exc:  # noqa: BLE001 - surface any launch/read failure
        message = f"Scan failed: {exc}"
        logger.exception("Scan %s failed", scan_id)
        try:
            await asyncio.to_thread(
                db.update_scan_status, scan_id, "failed", error_message=message, db_path=db_path
            )
        except Exception:  # noqa: BLE001 - DB may be unusable; queue still reports
            pass
        await queue.put({"type": "error", "message": message})
    finally:
        if proc is not None and proc.returncode is None:
            await _kill_process_group(proc)
        _scan_lock.release()
