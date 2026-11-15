# HauntScan MVP — Requirements

## Overview

HauntScan is a single-user web dashboard that runs authorized recon scans against a target domain and presents findings live. It shells out to the NucleiFuzzer toolchain, streams progress via Server-Sent Events, and stores every scan in SQLite. The UI uses a haunted house theme with dark background, eerie green, pumpkin orange, and ghost-purple accents.

---

## 1. New Scan Form

### User Stories

**US-1.1** WHEN the user opens the app, it SHALL display a "New Scan" form with a target domain field, a scan profile selector (Quick / Full), and an authorization checkbox.

**US-1.2** WHEN the user submits the form, the frontend SHALL prevent submission if the authorization checkbox is unchecked and SHALL display an inline error message.

**US-1.3** WHEN the user submits a target, the backend SHALL validate that the value is a syntactically valid public hostname or domain name (e.g. `example.com`, `sub.example.com`).

**US-1.4** WHEN the submitted target is a private/reserved IP address (RFC 1918: `10.x`, `172.16–31.x`, `192.168.x`), loopback (`127.x`), link-local (`169.254.x`), or IPv6 loopback (`::1`), the backend SHALL reject the request with HTTP 422 and a descriptive error message.

**US-1.5** WHEN the submitted target is the literal string `localhost`, the backend SHALL reject the request with HTTP 422.

**US-1.6** WHEN the backend receives a scan request without `authorized: true`, it SHALL reject the request with HTTP 422.

**US-1.7** WHEN a scan is already running, the backend SHALL reject a new scan request with HTTP 409 and the message "A scan is already in progress."

**US-1.8** WHEN target validation passes and no scan is in progress, the backend SHALL create a new scan record in SQLite (target, profile, timestamp, status = `running`) and return the new scan ID.

### Acceptance Criteria

- Submitting with no checkbox → frontend shows error, no API call made.
- Submitting `localhost` → API returns 422.
- Submitting `192.168.1.1` → API returns 422.
- Submitting `example.com` while another scan is running → API returns 409.
- Submitting `example.com` with checkbox checked and no scan running → API returns 201 with `scan_id`.
- SQLite row exists after a successful submission with status `running` and correct target/timestamp.

---

## 2. Live Progress Streaming

### User Stories

**US-2.1** WHEN a scan starts, the backend SHALL run the scan pipeline in a background task and emit log lines over a Server-Sent Events (SSE) endpoint at `/api/scans/{scan_id}/stream`.

**US-2.2** WHEN the frontend receives an SSE connection for a scan, it SHALL display each log line in a scrollable, monospace log panel in real time.

**US-2.3** WHEN the frontend is streaming, it SHALL display a progress bar that advances through named stages: Discovery → Probing → Scanning → Done.

**US-2.4** WHEN the scan subprocess exceeds the configured hard timeout, the backend SHALL kill the process, mark the scan `failed` in SQLite, and emit a final SSE event indicating timeout.

**US-2.5** WHEN the scan finishes successfully, the backend SHALL mark the scan `completed` in SQLite, emit a final `done` SSE event, and the frontend SHALL transition automatically to the Findings view.

**US-2.6** WHEN the scan fails, the frontend SHALL display an error state with the reason from the final SSE event.

### Acceptance Criteria

- `/api/scans/{scan_id}/stream` returns `Content-Type: text/event-stream`.
- Log lines appear in the UI within 1 second of being emitted by the subprocess.
- Progress bar transitions through all four stages in order.
- Forcing a timeout (via a very short timeout value in test config) results in scan status `failed` in DB.
- After `done` event, the UI shows the Findings section populated.

---

## 3. Findings Table, Filters, and Detail

### User Stories

**US-3.1** WHEN a scan completes (live or reopened from history), the frontend SHALL display a findings table with columns: Severity, Template Name, Matched URL, and Description.

**US-3.2** WHEN the findings table is shown, it SHALL be sorted by severity (critical → high → medium → low → info) by default.

**US-3.3** WHEN the user selects a severity filter, the table SHALL show only findings matching that severity; selecting "All" restores the full list.

**US-3.4** WHEN the user clicks a finding row, the frontend SHALL display a detail panel/modal showing all available fields: severity, template ID, matched URL, description, and raw evidence (matcher name, extracted values, curl command if present).

**US-3.5** WHEN there are no findings, the frontend SHALL display a "Nothing lurking here" placeholder message.

**US-3.6** WHEN the backend parses nuclei JSONL output, it SHALL extract for each finding: `template-id`, `info.severity`, `matched-at`, `info.name`, `info.description`, and the `evidence` block (matcher name, extracted values).

### Acceptance Criteria

- Findings from a completed scan appear in the table in severity order.
- Clicking a severity chip filters the table; clicking again or selecting "All" resets.
- Clicking a row opens a detail view with all fields populated.
- If the JSONL line is malformed, the backend logs a warning and skips that line without crashing.
- An empty scan result renders the placeholder, not an empty table with headers.

---

## 4. Scan History

### User Stories

**US-4.1** WHEN the user opens the History section, it SHALL display all past scans in reverse chronological order with: target domain, scan profile, start timestamp, duration, final status, and finding counts by severity.

**US-4.2** WHEN the user clicks a past scan row, the frontend SHALL load that scan's findings and display them in the Findings section.

**US-4.3** WHEN a scan's status is `running`, the history list SHALL show a live indicator and link to the active progress view.

**US-4.4** WHEN the backend serves history, it SHALL never expose a delete or purge endpoint; records are append-only.

### Acceptance Criteria

- After completing a scan, it appears at the top of the history list.
- Clicking a completed history row populates the Findings table with that scan's findings.
- Clicking a running history row navigates to the live progress view for that scan.
- No DELETE `/api/scans` endpoint exists.

---

## 5. Demo Mode

### User Stories

**US-5.1** WHEN the user clicks "Run Demo", the frontend SHALL POST to `/api/scans/demo` without requiring a real target domain or network access.

**US-5.2** WHEN the demo scan starts, the backend SHALL load findings from the canned fixture file at `tests/fixtures/demo_scan.jsonl` and replay them through the same SSE stream as a live scan.

**US-5.3** WHEN demo mode is active, the backend SHALL write a demo scan record to SQLite (target = `demo.hauntscan.local`, profile = `Quick`) so it appears in history.

**US-5.4** WHEN demo mode runs, it SHALL not invoke any external subprocess or make any network requests.

### Acceptance Criteria

- `/api/scans/demo` returns a scan ID and streams findings without network.
- Demo findings appear in the Findings table with correct severity ordering.
- Demo scan appears in History after completion.
- Running demo with no network connection succeeds.

---

## 6. Safety Rules

### User Stories

**US-6.1** WHEN any scan request arrives, the backend SHALL enforce backend-side target validation independently of any frontend check.

**US-6.2** WHEN the scan engine assembles the subprocess command, it SHALL never include `--validate`, `sqlmap`, `dalfox`, or any other active-exploitation flag or tool name.

**US-6.3** WHEN a scan subprocess is launched, the backend SHALL enforce a hard timeout (configurable, default 1800 seconds); on expiry it SHALL send SIGKILL to the process group and mark the scan `failed`.

**US-6.4** WHEN a second scan request arrives while one is already running, the backend SHALL return HTTP 409; there is never more than 1 concurrent scan process.

**US-6.5** WHEN any scan is created, the backend SHALL write to SQLite: target domain, scan profile, start timestamp, and status; this record SHALL never be deleted by the application.

**US-6.6** WHEN the authorization checkbox is unchecked, both the frontend (before submitting) and the backend (on receipt) SHALL refuse to start the scan.

### Acceptance Criteria

- A scan request with a private IP reaches the backend and is rejected 422, even if the frontend check were bypassed.
- Inspecting the assembled subprocess command never reveals `--validate`, sqlmap, or dalfox.
- A timed-out scan is recorded in SQLite as `failed` with a non-null `ended_at`.
- A second concurrent POST to `/api/scans` returns 409.
- SQLite has a row for every scan attempt that passed initial validation, with no rows deleted.
