# HauntScan MVP — Design

## 1. Architecture Overview

```
Browser
  │  HTTP GET /           → index.html (StaticFiles)
  │  HTTP GET /style.css  → style.css  (StaticFiles)
  │  HTTP GET /app.js     → app.js     (StaticFiles)
  │
  │  POST /api/scans          → start scan
  │  POST /api/scans/demo     → start demo scan
  │  GET  /api/scans          → list history
  │  GET  /api/scans/{id}     → scan detail + findings
  │  GET  /api/scans/{id}/stream  → SSE log stream
  └──────────────────────────────────────────────────
                FastAPI (backend/main.py)
                 │
                 ├─ routers/scans.py      scan CRUD + SSE
                 ├─ routers/findings.py   findings read
                 │
                 ├─ scan/runner.py        subprocess wrapper
                 ├─ scan/parser.py        nuclei JSONL parser
                 ├─ scan/validator.py     target validation
                 │
                 └─ db/database.py        SQLite init + queries
                      (stdlib sqlite3, WAL mode)
```

The app is a single Python process. FastAPI handles HTTP and SSE. The scan pipeline runs as an `asyncio` background task. SQLite is accessed synchronously via `sqlite3` wrapped in `asyncio.to_thread` calls to avoid blocking the event loop.

---

## 2. Backend

### 2.1 Entry Point — `backend/main.py`

- Creates the FastAPI app instance.
- Mounts `frontend/` as `StaticFiles` at `/` with `html=True` (serves `index.html` for `/`).
- Calls `db.database.init_db()` on startup via `@app.on_event("startup")`.
- Includes routers: `routers.scans` and `routers.findings`.
- Sets CORS to localhost only (single-user local app).

### 2.2 Routers

#### `backend/routers/scans.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scans` | Validate target, create scan record, enqueue background task |
| POST | `/api/scans/demo` | Create demo scan record, enqueue demo replay task |
| GET | `/api/scans` | Return all scan rows (history), newest first |
| GET | `/api/scans/{scan_id}` | Return single scan row + its findings |
| GET | `/api/scans/{scan_id}/stream` | SSE stream of log lines for a scan |

#### `backend/routers/findings.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/findings?scan_id={id}` | Return findings for a scan, ordered by severity rank |

### 2.3 Request / Response Shapes

**POST `/api/scans` request body**
```json
{
  "target": "example.com",
  "profile": "quick",
  "authorized": true
}
```

**POST `/api/scans` success response — HTTP 201**
```json
{
  "scan_id": 1,
  "target": "example.com",
  "profile": "quick",
  "status": "running",
  "created_at": "2026-11-14T10:00:00Z"
}
```

**GET `/api/scans` response**
```json
[
  {
    "scan_id": 1,
    "target": "example.com",
    "profile": "quick",
    "status": "completed",
    "created_at": "...",
    "ended_at": "...",
    "duration_seconds": 142,
    "finding_counts": {"critical": 0, "high": 1, "medium": 3, "low": 2, "info": 5}
  }
]
```

**GET `/api/scans/{scan_id}` response**
```json
{
  "scan_id": 1,
  "target": "example.com",
  "profile": "quick",
  "status": "completed",
  "created_at": "...",
  "ended_at": "...",
  "findings": [/* Finding objects */]
}
```

**SSE event format** (each `data:` line is a JSON object)
```
data: {"type": "log", "message": "[discovery] fetching URLs..."}

data: {"type": "stage", "stage": "probing"}

data: {"type": "finding", "finding": {/* Finding object */}}

data: {"type": "done", "status": "completed"}

data: {"type": "error", "message": "Scan timed out after 1800s"}
```

**Finding object**
```json
{
  "finding_id": 42,
  "scan_id": 1,
  "template_id": "cve-2021-44228",
  "severity": "critical",
  "name": "Log4Shell RCE",
  "matched_url": "https://example.com/api/login",
  "description": "Remote code execution via JNDI lookup in log4j.",
  "matcher_name": "word",
  "extracted_results": ["${jndi:...}"],
  "curl_command": "curl -X POST ..."
}
```

---

## 3. Data Models

### 3.1 `scans` table

```sql
CREATE TABLE IF NOT EXISTS scans (
    scan_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL,
    profile       TEXT    NOT NULL CHECK(profile IN ('quick', 'full')),
    status        TEXT    NOT NULL DEFAULT 'running'
                          CHECK(status IN ('running', 'completed', 'failed')),
    created_at    TEXT    NOT NULL,   -- ISO-8601 UTC
    ended_at      TEXT,               -- NULL until terminal state
    error_message TEXT                -- populated on failure
);
```

### 3.2 `findings` table

```sql
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
    extracted_results TEXT,   -- JSON array stored as TEXT
    curl_command      TEXT
);
```

Severity sort order for queries: `critical=0, high=1, medium=2, low=3, info=4`.

---

## 4. Scan Engine

### 4.1 `backend/scan/validator.py`

`validate_target(target: str) -> None` raises `ValueError` with a human-readable message on:

- Empty or whitespace-only string.
- Fails `re` hostname/domain pattern (labels 1–63 chars, alphanumeric + hyphen, no leading/trailing hyphen, TLD required).
- Is a bare IP address in a private/reserved range (parsed via `ipaddress` stdlib).
  - RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Loopback: `127.0.0.0/8`
  - Link-local: `169.254.0.0/16`
  - IPv6 loopback: `::1/128`
- Exact match on `localhost` (case-insensitive).

DNS resolution of the target is NOT performed at validation time (the target may be a not-yet-live hostname on a bug bounty program). Only the syntactic/IP checks are enforced.

### 4.2 `backend/scan/runner.py`

`run_scan(scan_id: int, target: str, profile: str, queue: asyncio.Queue) -> None`

- Builds the subprocess command for the chosen profile:
  - **Quick**: `nf -u {target}` (default NucleiFuzzer templates)
  - **Full**: `nf -u {target} -t fuzzing-templates` (extended template set)
- Never appends `--validate`, sqlmap, or dalfox to any command.
- Launches the subprocess with `asyncio.create_subprocess_exec`, stdout/stderr piped, in its own process group (`os.setsid`).
- Reads stdout lines; for each line:
  - Puts a `{"type": "log", "message": line}` dict on `queue`.
  - If the line is valid JSON (nuclei JSONL), delegates to `parser.parse_finding` and puts a `{"type": "finding", "finding": ...}` dict on `queue`.
- Enforces a hard timeout via `asyncio.wait_for`. On timeout, sends `SIGKILL` to the process group via `os.killpg`.
- On completion, puts `{"type": "done", "status": "completed"}` or `{"type": "error", "message": ...}` on `queue`.
- Updates the `scans` row `status`, `ended_at`, and optionally `error_message` via the DB module.

**Concurrency gate**: a module-level `asyncio.Lock` (`_scan_lock`) guards the single-scan invariant. `run_scan` acquires it before launching; callers check `_scan_lock.locked()` before enqueueing.

### 4.3 `backend/scan/parser.py`

`parse_finding(line: str, scan_id: int) -> dict | None`

- Attempts `json.loads(line)`.
- Returns `None` and logs a warning if parsing fails.
- Extracts: `template-id`, `info.severity` (normalized to lowercase), `info.name`, `info.name` → description from `info.description`, `matched-at`, `matcher-name`, `extracted-results` (list), `curl-command`.
- Returns a dict matching the Finding schema above.
- Inserts the finding into SQLite via `db.database.insert_finding`.

### 4.4 Demo Mode — `backend/scan/demo.py`

`run_demo(scan_id: int, queue: asyncio.Queue) -> None`

- Reads `tests/fixtures/demo_scan.jsonl` line by line.
- Emits each line as a `{"type": "log", ...}` event with a small `asyncio.sleep(0.05)` delay to simulate streaming.
- Parses each JSONL line through `parser.parse_finding`.
- Emits `{"type": "stage", ...}` events at appropriate line counts to simulate stage transitions.
- Does not invoke any subprocess or network call.

---

## 5. Database Layer — `backend/db/database.py`

Thin wrapper around stdlib `sqlite3`.

**Functions:**
- `init_db(db_path: str) -> None` — creates tables if they don't exist, enables WAL mode.
- `create_scan(target, profile) -> int` — inserts a scan row, returns `scan_id`.
- `update_scan_status(scan_id, status, ended_at, error_message=None) -> None`
- `get_scan(scan_id) -> dict | None`
- `list_scans() -> list[dict]` — newest first; includes finding counts aggregated by severity.
- `insert_finding(finding: dict) -> int` — inserts a finding row, returns `finding_id`.
- `get_findings(scan_id: int) -> list[dict]` — ordered by severity rank.

All DB calls that happen inside async route handlers are wrapped in `asyncio.to_thread(...)`.

---

## 6. SSE Streaming

`GET /api/scans/{scan_id}/stream` is a `StreamingResponse` with `media_type="text/event-stream"`.

The route:
1. Looks up the scan; returns 404 if not found.
2. If `status` is already `completed` or `failed`, reads all findings from DB and replays them as SSE events, then emits `done`. (Supports reopening a finished scan.)
3. If `status` is `running`, subscribes to the in-memory `asyncio.Queue` for that scan and yields events as they arrive.
4. Each event is formatted as `data: {json}\n\n`.
5. On client disconnect, the generator exits cleanly without killing the scan.

Each scan has an associated queue stored in a module-level dict keyed by `scan_id`. The queue is created before the background task starts and cleaned up after the done event is consumed.

---

## 7. Frontend

Single HTML page at `frontend/index.html`. All state is managed in `frontend/app.js`. Styles in `frontend/style.css`.

### 7.1 Sections (shown/hidden via CSS class toggling)

| Section | Trigger |
|---------|---------|
| `#section-new-scan` | Default / clicking "New Scan" in nav |
| `#section-live-scan` | After scan starts |
| `#section-findings` | After scan completes or reopening history row |
| `#section-history` | Clicking "History" in nav |

### 7.2 New Scan Form

Fields: `target` (text), `profile` (select: quick/full), `authorized` (checkbox). Submit calls `POST /api/scans`. On success, navigates to live scan section and opens SSE stream.

### 7.3 Live Scan View

- Log panel: `<pre>` element, auto-scrolls to bottom on new lines.
- Progress bar: 4 segments (Discovery, Probing, Scanning, Done); each `stage` SSE event advances the bar.
- On `done` event: hides live view, calls `GET /api/scans/{id}` to load findings, shows Findings section.

### 7.4 Findings Table

- `<table>` with `<tbody>` populated from the findings array.
- Severity chips styled with per-severity color (critical = red-orange, high = orange, medium = yellow, low = eerie-green, info = ghost-purple).
- Severity filter buttons above the table; active filter highlighted.
- Row click → detail panel (a `<dialog>` element) with all Finding fields.

### 7.5 History List

- Loaded on nav click via `GET /api/scans`.
- Each row: target, profile badge, status icon, timestamp, duration, finding count chips.
- Running scan row links to live scan view; completed row calls `GET /api/scans/{id}` and loads findings.

### 7.6 Haunted Theme

- CSS custom properties for the palette: `--clr-bg`, `--clr-surface`, `--clr-green`, `--clr-orange`, `--clr-purple`, `--clr-text`, `--clr-muted`.
- Background: near-black (`#0d0d0f`) with a radial gradient fog effect using the purple/green palette.
- Fonts: `Share Tech Mono` (monospace, CDN) for log panel; system sans-serif for body.
- Ghost/pumpkin emoji used sparingly as decorative elements in headings and status labels.
- No animations that hurt readability; subtle CSS `opacity` pulse on the running indicator only.

---

## 8. Error Handling

| Scenario | Behavior |
|----------|----------|
| `authorized: false` in request body | 422 Unprocessable Entity, `{"detail": "Authorization required."}` |
| Invalid/private target | 422, `{"detail": "<reason>"}` |
| Scan already running | 409 Conflict, `{"detail": "A scan is already in progress."}` |
| Scan ID not found | 404 Not Found |
| Subprocess timeout | Scan marked `failed`, final SSE event `{"type":"error","message":"Scan timed out after {N}s"}` |
| Malformed JSONL line | Warning logged, line skipped, scan continues |
| DB error on write | 500 Internal Server Error; scan marked `failed` if mid-run |

Frontend displays API error `detail` strings inline in the form or in a dismissible toast.

---

## 9. Configuration

Environment variables (with defaults, read in `backend/main.py`):

| Variable | Default | Description |
|----------|---------|-------------|
| `HAUNTSCAN_DB_PATH` | `hauntscan.db` | SQLite file path |
| `HAUNTSCAN_SCAN_TIMEOUT` | `1800` | Hard timeout in seconds |
| `HAUNTSCAN_DEMO_FIXTURE` | `tests/fixtures/demo_scan.jsonl` | Demo fixture path |

---

## 10. Testing Strategy

Tests live in `tests/`. Run with `pytest` from repo root.

| Test module | What it covers |
|-------------|----------------|
| `test_validator.py` | Valid domains accepted; private IPs, localhost, malformed strings rejected |
| `test_parser.py` | Nuclei JSONL lines parsed correctly; malformed lines return None |
| `test_db.py` | CRUD operations on in-memory SQLite (`":memory:"`) |
| `test_scans_api.py` | POST `/api/scans` validation, 409 on concurrent, 404 on missing scan |
| `test_demo.py` | Demo endpoint returns 201, streams findings from fixture, no subprocess |
| `test_findings_api.py` | GET findings returns correct severity order |

No tests invoke real network calls or external tools. The scan runner is tested by injecting a fake subprocess via `unittest.mock`.
