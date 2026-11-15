# HauntScan — Project Brief for Kiro

## Product

HauntScan is a web dashboard that runs authorized web-recon scans for bug
bounty hunters and shows the results live. The user enters a target domain,
confirms they are authorized to test it, and HauntScan runs the recon
pipeline (URL/subdomain discovery → live-host probing → Nuclei DAST scan),
streams progress live, and presents findings grouped by severity with
evidence (matched template, URL, severity, description).

## Category

Kiroween 2026 — **Costume Contest**: any app, but the UI must be polished
and haunting. The theme is a haunted house / ghost hunt: dark background,
eerie green + pumpkin orange + ghost-purple accents, subtle fog and ghost
motifs, playful copy ("Scan the darkness", "Something is hiding here").
The theme must enhance the function, not obscure it: severity must stay
readable at a glance, and the scan log must stay legible.

## Users

Beginner bug bounty hunters (like the author) who know the recon tools exist
but find the terminal workflow painful, and who want one place to run a scan
and triage what came back.

## MVP scope (must ship)

1. **New scan**: form with target domain + authorization checkbox + scan
   profile (Quick / Full). Target validation: valid domain/hostname only,
   no private/reserved IPs, no localhost.
2. **Live progress**: scan runs as a background job; the UI streams log
   lines (discovery → probing → scanning → done) and a progress bar.
3. **Findings**: table of findings with severity (critical/high/medium/low/
   info), template name, matched URL, description; filter by severity;
   click a finding for detail.
4. **History**: list of past scans with status, target, finding counts,
   duration; reopen any scan.
5. **Demo mode**: a canned scan result (from a fixture file) so the app can
   be demonstrated without running a live scan.
6. **Safety**: authorization checkbox required; no active exploitation
   (`--validate`, sqlmap, dalfox) anywhere in the app; scan timeout and a
   max of 1 concurrent scan; every scan logged with target + timestamp.

## Non-goals for MVP

- User accounts / login. Single-user local app.
- Scheduled / recurring scans.
- Auto-exploitation or payload validation.
- Multi-target bulk scanning.

## Tech decisions (fixed)

- Backend: Python 3.12, FastAPI, SQLite (via stdlib `sqlite3` or
  SQLAlchemy — keep it simple), pytest.
- Scan engine: shell out to the installed NucleiFuzzer toolchain
  (`nf` CLI and/or the underlying tools: waybackurls, gauplus, katana,
  hakrawler, httpx, nuclei). Parse nuclei JSONL output.
- Frontend: no build step. Plain HTML/CSS/JS in `frontend/`, served by
  FastAPI static files. One page, sections for New Scan / Live Scan /
  Findings / History.
- The repo root must contain `.kiro/` with specs, steering, and hooks.
  Never add `.kiro` to `.gitignore`.

## Definition of done

- `pytest` passes.
- A scan of an authorized demo target completes end-to-end and its
  findings render in the UI.
- Demo mode works with no network.
- README documents how to run it and the safety rules.
