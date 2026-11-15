# HauntScan MVP — Tasks

Derived from `requirements.md` and `design.md`. Work in order; check off each
task only when its verification step passes.

## 1. Project scaffold + dependencies

Create `backend/`, `frontend/`, `tests/`; add `backend/requirements.txt`
(fastapi, uvicorn, pytest, httpx) and a root `.gitignore` (Python, venv,
`*.db`, `__pycache__` — never `.kiro/`).
Verify: `pip install -r backend/requirements.txt` succeeds; `pytest` runs
(0 tests, exit 0).

## 2. Target validator + safety rules

Implement `backend/scan/validator.py`: accept only valid public domains/
hostnames; reject private/reserved IPs (RFC 1918, loopback, link-local),
`localhost`, and hostnames resolving to private addresses.
Verify: `tests/test_validator.py` passes (valid domains accepted; private
IPs, localhost, malformed strings rejected).

## 3. Nuclei JSONL parser

Implement `backend/scan/parser.py`: parse one nuclei JSONL line into a
Finding (severity, template-id, matched URL, name, description, tags);
malformed lines return None and are counted, never crash the scan.
Verify: `tests/test_parser.py` passes on fixture lines (valid + malformed).

## 4. SQLite store ✅ DONE 2026-11-15 — `backend/db/database.py` + `tests/test_db.py`
(11 tests, in-memory DB); full suite 47 passed. Logs are NOT persisted per
design §6 (SSE live queue only); `insert_finding` raises on severity
`"unknown"` instead of storing a wrong severity.

Implement `backend/db/database.py` (stdlib `sqlite3`, WAL mode): tables
`scans` and `findings`; functions to create a scan, append log lines,
upsert findings, update scan status, list scans, get one scan with findings.
Verify: `tests/test_db.py` passes against an in-memory database.

## 5. Scan runner ✅ DONE 2026-11-15 — `backend/scan/runner.py` +
`tests/test_runner.py` (8 tests); full suite 55 passed. Deviations from
design §4.2/§4.3, documented in `runner.py`: the parser as built (task 3)
is `parse_line(line) -> Finding` with no DB side effect, so the runner
does the SQLite insert itself (via `asyncio.to_thread`); findings with
severity `"unknown"` are logged and skipped, not stored (DB CHECK
constraint). Real-subprocess check done with a local `python -c` command
printing canned JSONL (test hook `command=`); a real `nf` run against a
demo target is still untested and needs network + templates.

Implement `backend/scan/runner.py`: run the pipeline as an asyncio
background task — discovery (waybackurls/gauplus/katana/hakrawler) →
probing (httpx) → nuclei DAST scan (JSONL output). Enforce a hard timeout
(default 1800 s, SIGKILL the process group on expiry), max 1 concurrent
scan (second start returns an error), and stream log lines to the store.
Never assemble a command containing `--validate`, sqlmap, or dalfox.
Verify: mocked-subprocess test passes; a real run against a demo target
completes and writes findings.

## 6. FastAPI endpoints + SSE progress ✅ DONE 2026-11-15 — `backend/main.py` + `backend/routers/scans.py` + `backend/routers/findings.py` + `backend/scan/demo.py` + `tests/test_scans_api.py` (11 tests); full suite 66 passed. Deviations from design §2.1/§4.4, documented in code: demo replay (`run_demo`) implemented now but the fixture `tests/fixtures/demo_scan.jsonl` arrives in task 8, so a demo scan currently fails fast with a clear "fixture not found" error (SSE replays it); `/api/health` is defined before the StaticFiles mount so the mount cannot shadow it. `GET /api/scans/{id}/stream` replays findings + done/error for finished scans, subscribes to the live queue while running, and leaves the queue registered on client disconnect (never kills the scan).

Implement `backend/main.py` + routers: `POST /api/scans` (validate body,
require `authorized: true`, 422 on bad target, 409 when a scan is running),
`POST /api/scans/demo`, `GET /api/scans`, `GET /api/scans/{id}`,
`GET /api/scans/{id}/stream` (SSE log stream), static files for `/`.
Verify: `tests/test_scans_api.py` passes; `curl` the endpoints with the
server running.

## 7. Frontend — haunted dashboard ✅ DONE 2026-11-15 — `frontend/index.html` +
`frontend/style.css` + `frontend/app.js` (no build step); full suite 66 passed.
Kiro CLI tried once 2026-11-15 and failed again with ModelRegistryUnavailableError
(registry still down since 2026-11-14 ~19:21 WIB), so the frontend was implemented
by Muse per design §7. Live view shows a running count of findings found so far
(small addition, not in the spec). Verified with curl against a live uvicorn:
`/api/health` ok, `/` serves index.html, style.css/app.js 200, 422 on no-auth and
localhost targets, demo POST 201 and the SSE stream honestly reports the
"Demo fixture not found" error (fixture is task 8), SSE replay of the failed scan
re-emits the error, history + findings endpoints 200; `node --check app.js` OK.
Test server stopped afterwards, port 8473 free. Live-browser click-through
(form submit, SSE progress rendering) was NOT verified by this agent — no live
browser access from a subagent; left for the main agent.

## 8. Demo mode fixture ✅ DONE 2026-11-15 — `tests/fixtures/demo_scan.jsonl` (8 canned findings: 1 critical, 2 high, 2 medium, 1 low, 2 info, target demo.hauntscan.local) + `tests/test_demo.py` (3 tests); full suite 69 passed. Fixture path follows requirements US-5.2 / design §4.4 / demo.py default (`tests/fixtures/demo_scan.jsonl`), NOT tasks.md's one-liner (`backend/fixtures/demo-scan.jsonl`) — no code change needed. Verified live: POST /api/scans/demo → 201, SSE streams 8 finding events, scan completes with 8 findings stored. Browser click-through NOT possible: the live browser runs on a separate VM that blocks loopback addresses and has no reachable address for this VM's server (no public URL/tunnel); the user cannot open it on their phone either (app runs on this VM, not the phone). Frontend rendering/filtering verified only via API + tests so far.

Add `backend/fixtures/demo-scan.jsonl` (canned nuclei-style findings for a
fake target) and wire `POST /api/scans/demo` to stream it through the same
code path as a real scan, with no subprocess and no network.
Verify: `tests/test_demo.py` passes; demo scan completes in the UI.

## 9. Tests + README ✅ DONE 2026-11-15 — `tests/test_findings_api.py` (4 tests: severity ordering, fields, empty scan, 404); full suite 73 passed. Root README rewritten (install, run, demo, API table, safety rules, layout, status). Verified on a clean checkout in /tmp: fresh venv + pip install + pytest 73 passed + uvicorn smoke test (health ok, GET / 200, demo scan completed with 8 findings). Clean-checkout dir removed afterwards.

Finish the pytest suite (`test_findings_api.py` — severity ordering;
all modules green), then update the root README with how to install, run,
and the safety rules.
Verify: `pytest` fully green from repo root; README instructions work on a
clean checkout.
