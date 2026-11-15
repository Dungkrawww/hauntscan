# Tech Stack

## Backend

- **Python 3.12** — required version.
- **FastAPI** — HTTP API and static file serving. Use `async def` handlers where possible.
- **SQLite** — scan history via stdlib `sqlite3` or SQLAlchemy (no migrations framework needed for MVP).
- **pytest** — all tests live in `tests/`; run with `pytest` from the repo root.

## Scan engine

Shell out to the NucleiFuzzer toolchain installed on the machine:

- `nf` — NucleiFuzzer CLI (top-level orchestrator).
- Underlying tools: `waybackurls`, `gauplus`, `katana`, `hakrawler`, `httpx`, `nuclei`, `ParamSpider`.
- Parse nuclei JSONL output to extract findings (severity, template, URL, description, evidence).
- Never add `--validate`, sqlmap, or dalfox invocations anywhere in the codebase.

## Frontend

- Plain HTML / CSS / JS in `frontend/` — no build step, no bundler, no npm.
- Served by FastAPI `StaticFiles` mount.
- Single page with sections: New Scan, Live Scan, Findings, History.
- Uses `fetch` / `EventSource` for live log streaming.
- Styling in companion CSS file(s); CDN links are acceptable for fonts or icons only.

## Key constraints

- No build pipeline. Files saved to `frontend/` are served as-is.
- No TypeScript compilation, no Webpack, no Vite.
- Backend dependencies managed with `pip` and a `requirements.txt`.
