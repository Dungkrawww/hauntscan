# Repo Layout and File Conventions

## Directory structure

```
kiroween/
├── .kiro/
│   ├── steering/       # These steering docs
│   ├── specs/          # Feature specs
│   └── hooks/          # Agent hooks
├── backend/
│   ├── main.py         # FastAPI app entry point
│   ├── scan/           # Scan engine: subprocess wrapper, JSONL parser
│   ├── db/             # SQLite schema and queries
│   └── routers/        # FastAPI route modules
├── frontend/
│   ├── index.html      # Single-page app
│   ├── style.css       # Haunted theme styles
│   └── app.js          # UI logic, fetch/EventSource calls
├── tests/
│   ├── fixtures/        # Canned scan output for demo mode and tests
│   └── test_*.py       # pytest test modules
├── requirements.txt
├── README.md
└── PROJECT-BRIEF.md
```

## File conventions

- Python files use `snake_case` for modules and functions, `PascalCase` for classes.
- One FastAPI router per logical resource (e.g. `routers/scans.py`, `routers/findings.py`).
- Fixture files for demo mode live in `tests/fixtures/` as JSONL (nuclei output format).
- `.kiro/` is never added to `.gitignore`.
- No generated or compiled files are committed (no `__pycache__`, no `.pyc`).
