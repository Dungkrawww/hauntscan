# HauntScan — Web Recon Dashboard for Bug Bounty Hunters

**Kiroween 2026 — Costume Contest category**

HauntScan wraps the NucleiFuzzer recon pipeline (subdomain/URL discovery,
live probing, Nuclei DAST scanning) in a haunted, Halloween-themed web
dashboard. A hunter enters a target they are authorized to test, watches the
scan unfold live like a ghost hunt, and triages findings by severity.

## Why this exists

Bug bounty recon today is a pile of terminal commands. HauntScan makes it
visible: one scan, one dashboard, every finding in one place — so a beginner
hunter can run a proper recon workflow without memorizing a dozen CLI flags.

## Safety first

- **Only scan targets you own or are explicitly authorized to test**
  (bug bounty program scope, your own domains, deliberately vulnerable
  labs). The backend rejects private/reserved IPs, `localhost`, and
  hostnames resolving to private addresses.
- **HauntScan never runs active exploitation.** No `--validate`, sqlmap, or
  dalfox — ever. It runs discovery + probing + Nuclei DAST scanning only.
- Every scan requires an explicit authorization checkbox; the API rejects
  the request (422) without it.
- At most **one scan at a time** (a second start gets 409), and every scan
  has a **hard 1800 s timeout** (the process group is SIGKILLed on expiry).
- Run the server bound to **127.0.0.1 only** (see below) — do not expose it
  publicly. Every scan is logged to SQLite and never deleted.

## Install

Requires Python 3.12+ and, for real scans, the NucleiFuzzer toolchain
(`nf`, `nuclei`, `httpx`, `katana`, `waybackurls`, `gauplus`, `hakrawler`)
on `PATH`. Demo mode needs no tools at all.

```bash
git clone <this-repo>
cd hauntscan
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
```

## Run

```bash
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Then open http://127.0.0.1:8000/ — the dashboard. Scan history is stored in
`hauntscan.db` (SQLite, WAL mode) in the working directory.

To try it without any target or tools, click **Run demo**: it replays 8
canned findings through the same live SSE stream as a real scan, with no
subprocess and no network.

Environment variables (all optional):

| Variable | Default | What it does |
| --- | --- | --- |
| `HAUNTSCAN_DB_PATH` | `hauntscan.db` | SQLite database file |
| `HAUNTSCAN_DEMO_FIXTURE` | `tests/fixtures/demo_scan.jsonl` | Demo fixture file |

## API

| Method | Endpoint | What it does |
| --- | --- | --- |
| GET | `/api/health` | `{"status": "ok"}` |
| POST | `/api/scans` | Start a scan (`target`, `profile`: `quick`/`full`, `authorized: true`). 422 bad target / no authorization, 409 scan already running |
| POST | `/api/scans/demo` | Start a demo scan (no target needed) |
| GET | `/api/scans` | Scan history |
| GET | `/api/scans/{id}` | One scan with its findings |
| GET | `/api/scans/{id}/stream` | SSE live log + findings (replays finished scans) |
| GET | `/api/findings?scan_id={id}` | Findings ordered critical → high → medium → low → info |

## Tests

```bash
.venv/bin/python -m pytest -q
```

73 tests, all passing: validator, parser, SQLite store, scan runner
(mocked subprocess), API + SSE, demo replay, findings ordering.

## Project layout

```
.kiro/               # Kiro specs, steering, hooks (required for Kiroween)
backend/
  main.py           # FastAPI app, static frontend mount
  db/database.py    # SQLite store (scans + findings)
  routers/          # scans + findings API
  scan/             # validator, parser, runner, demo replay
  fixtures/         # (reserved; demo fixture lives in tests/fixtures/)
frontend/           # static SPA: index.html, style.css, app.js
tests/              # pytest, incl. fixtures/demo_scan.jsonl
```

## Status

MVP complete (tasks 1–9, 73 tests green), built during the Kiroween 2026
submission period (30 Oct – 4 Dec 2026). Steering docs, requirements, and
design were generated with Kiro (spec-driven development); implementation
followed that spec while Kiro's model registry was down.
