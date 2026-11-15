"""SQLite store for HauntScan (task 4).

Thin wrapper around stdlib ``sqlite3`` following ``.kiro/specs/*/design.md``
sections 3 and 5. Tables ``scans`` and ``findings`` exactly as specified
there; no extra tables.

Notes on the spec:
- Scan log lines are NOT persisted. Per design section 6 they stream live
  over SSE via an in-memory ``asyncio.Queue``; a finished scan is reopened
  by replaying its findings from this store, not its logs.
- ``findings.severity`` is CHECK-constrained to the five real severities.
  A parser ``Finding`` with severity ``"unknown"`` must be skipped or
  reclassified by the caller — :func:`insert_finding` raises ``ValueError``
  for it rather than silently storing a wrong severity.
- All functions take an optional ``db_path`` and default to the path set by
  the most recent :func:`init_db` call (or ``HAUNTSCAN_DB_PATH`` /
  ``hauntscan.db``). Connections are cached per path behind a lock so that
  ``":memory:"`` databases stay usable across calls and the same connection
  can be used from ``asyncio.to_thread`` workers.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}
PROFILES = ("quick", "full")
STATUSES = ("running", "completed", "failed")

_DEFAULT_PATH = os.environ.get("HAUNTSCAN_DB_PATH", "hauntscan.db")

_lock = threading.Lock()
_connections: dict[str, sqlite3.Connection] = {}
_db_path = _DEFAULT_PATH

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL,
    profile       TEXT    NOT NULL CHECK(profile IN ('quick', 'full')),
    status        TEXT    NOT NULL DEFAULT 'running'
                          CHECK(status IN ('running', 'completed', 'failed')),
    created_at    TEXT    NOT NULL,
    ended_at      TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(scan_id),
    template_id       TEXT    NOT NULL,
    severity          TEXT    NOT NULL
                              CHECK(severity IN ('critical','high','medium','low','info')),
    name              TEXT,
    matched_url       TEXT,
    description       TEXT,
    matcher_name      TEXT,
    extracted_results TEXT,
    curl_command      TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _connect(db_path: str) -> sqlite3.Connection:
    """Return the cached connection for ``db_path``, creating it if needed."""
    conn = _connections.get(db_path)
    if conn is None:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # WAL is a no-op on :memory: (returns "memory"); harmless either way.
        conn.execute("PRAGMA journal_mode = WAL")
        _connections[db_path] = conn
    return conn


def _path(db_path: str | None) -> str:
    return db_path if db_path is not None else _db_path


def close(db_path: str | None = None) -> None:
    """Close cached connection(s); mainly for tests."""
    global _db_path
    with _lock:
        if db_path is None:
            for conn in _connections.values():
                conn.close()
            _connections.clear()
        elif db_path in _connections:
            _connections.pop(db_path).close()


def init_db(db_path: str | None = None) -> None:
    """Create the tables if they do not exist; remember ``db_path``."""
    global _db_path
    path = db_path if db_path is not None else _db_path
    _db_path = path
    with _lock:
        conn = _connect(path)
        conn.executescript(_SCHEMA)
        conn.commit()


def create_scan(target: str, profile: str, db_path: str | None = None) -> int:
    """Insert a scan row (status ``'running'``) and return its ``scan_id``."""
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}, got {profile!r}")
    if not target or not target.strip():
        raise ValueError("target must not be empty")
    with _lock:
        conn = _connect(_path(db_path))
        cur = conn.execute(
            "INSERT INTO scans (target, profile, status, created_at)"
            " VALUES (?, ?, 'running', ?)",
            (target.strip(), profile, _now_iso()),
        )
        conn.commit()
        return int(cur.lastrowid)


def update_scan_status(
    scan_id: int,
    status: str,
    ended_at: str | None = None,
    error_message: str | None = None,
    db_path: str | None = None,
) -> None:
    """Set a scan's status. Terminal statuses stamp ``ended_at`` (now if
    not given); a non-terminal status clears ``ended_at``/``error_message``
    unless explicitly provided."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}, got {status!r}")
    if status in ("completed", "failed") and ended_at is None:
        ended_at = _now_iso()
    with _lock:
        conn = _connect(_path(db_path))
        cur = conn.execute(
            "UPDATE scans SET status = ?, ended_at = ?, error_message = ?"
            " WHERE scan_id = ?",
            (status, ended_at, error_message, scan_id),
        )
        if cur.rowcount == 0:
            raise KeyError(f"no scan with scan_id={scan_id}")
        conn.commit()


def _finding_counts(conn: sqlite3.Connection, scan_id: int) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for row in conn.execute(
        "SELECT severity, COUNT(*) AS n FROM findings"
        " WHERE scan_id = ? GROUP BY severity",
        (scan_id,),
    ):
        counts[row["severity"]] = int(row["n"])
    return counts


def _duration_seconds(row: sqlite3.Row) -> float | None:
    if not row["ended_at"]:
        return None
    start = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(row["ended_at"].replace("Z", "+00:00"))
    return (end - start).total_seconds()


def _scan_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    return {
        "scan_id": row["scan_id"],
        "target": row["target"],
        "profile": row["profile"],
        "status": row["status"],
        "created_at": row["created_at"],
        "ended_at": row["ended_at"],
        "error_message": row["error_message"],
        "duration_seconds": _duration_seconds(row),
        "finding_counts": _finding_counts(conn, row["scan_id"]),
    }


def get_scan(scan_id: int, db_path: str | None = None) -> dict | None:
    """Return one scan as a dict (with ``finding_counts``), or None."""
    with _lock:
        conn = _connect(_path(db_path))
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return _scan_dict(conn, row) if row is not None else None


def get_scan_with_findings(
    scan_id: int, db_path: str | None = None
) -> dict | None:
    """Like :func:`get_scan`, plus a ``findings`` list in severity order."""
    scan = get_scan(scan_id, db_path=db_path)
    if scan is None:
        return None
    scan["findings"] = get_findings(scan_id, db_path=db_path)
    return scan


def list_scans(db_path: str | None = None) -> list[dict]:
    """All scans, newest first, each with ``finding_counts``."""
    with _lock:
        conn = _connect(_path(db_path))
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY scan_id DESC"
        ).fetchall()
        return [_scan_dict(conn, row) for row in rows]


def _field(finding, name: str, default=None):
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def insert_finding(finding, db_path: str | None = None) -> int:
    """Insert one finding (dict, or a parser ``Finding``) and return its id.

    Accepted keys/attributes: ``scan_id``, ``template_id``, ``severity``,
    ``name``, ``matched_url``, ``description``, ``matcher_name``,
    ``extracted_results`` (list, stored as JSON), ``curl_command``.
    ``severity`` must be one of the five real severities.
    """
    severity = str(_field(finding, "severity", "")).lower()
    if severity not in SEVERITIES:
        raise ValueError(
            f"severity must be one of {SEVERITIES}, got {severity!r}"
        )
    scan_id = _field(finding, "scan_id")
    template_id = _field(finding, "template_id")
    if scan_id is None or not template_id:
        raise ValueError("finding needs scan_id and template_id")
    extracted = _field(finding, "extracted_results") or []
    if isinstance(extracted, str):
        extracted = [extracted]
    with _lock:
        conn = _connect(_path(db_path))
        cur = conn.execute(
            "INSERT INTO findings (scan_id, template_id, severity, name,"
            " matched_url, description, matcher_name, extracted_results,"
            " curl_command) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                str(template_id),
                severity,
                _field(finding, "name"),
                _field(finding, "matched_url"),
                _field(finding, "description", ""),
                _field(finding, "matcher_name"),
                json.dumps(list(extracted)),
                _field(finding, "curl_command"),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_findings(scan_id: int, db_path: str | None = None) -> list[dict]:
    """Findings for a scan, ordered critical → high → medium → low → info."""
    with _lock:
        conn = _connect(_path(db_path))
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?"
            " ORDER BY CASE severity"
            "   WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
            "   WHEN 'medium' THEN 2 WHEN 'low' THEN 3"
            "   WHEN 'info' THEN 4 ELSE 5 END, finding_id",
            (scan_id,),
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            try:
                item["extracted_results"] = json.loads(
                    row["extracted_results"] or "[]"
                )
            except json.JSONDecodeError:
                item["extracted_results"] = []
            out.append(item)
        return out
