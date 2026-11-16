# HauntScan — Demo video script (<3 min) + Devpost outline

Draft prepared 2026-11-16 ~11:00 WIB, after the live URL went up.
Live app: https://hauntscan.onrender.com
Repo: https://github.com/Dungkrawww/hauntscan
Submission deadline: 5 Dec 2026 05:00 WIB (4 Dec 22:00 UTC), Kiroween Costume Contest.

## Before recording — warm up the free instance

Render Free spins down when idle. Open https://hauntscan.onrender.com
about 1 minute before recording and wait for the dashboard to load
(first load after idle can take ~50 s — verified ~22 s on a check at
~10:57 WIB, GET / returned 200). Do NOT record the cold-start wait.

Record in the browser at 1280x720 or larger, full dashboard visible.
Narration below is in simple English (judges read Devpost in English);
if recording in Indonesian feels more natural, keep the on-screen
actions identical and translate the lines — the timings still hold.

## Script — total ~2:40

### 0:00–0:20 — Hook: the problem (20 s)
On screen: HauntScan homepage.
Say: "Bug bounty recon means five terminal tools, five outputs, and
nowhere to triage them. HauntScan puts it in one dashboard — scan the
darkness, see every finding in one place."
Show: the dark haunted theme, "Scan the darkness" copy, New Scan form.

### 0:20–0:55 — Demo scan, live (35 s)
On screen: click **Run demo** (no target, no tools needed).
Say: "No target needed for the demo — it replays eight canned findings
through the same live stream a real scan uses."
Show: SSE live log lines appearing (discovery → probing → scanning →
done) and the progress bar moving. Keep this shot uncut so judges see
it is really streaming.

### 0:55–1:35 — Findings triage (40 s)
On screen: findings table once the demo scan finishes.
Say: "Eight findings, ordered critical to info, each with its template,
matched URL and description. Filter by severity, click one for detail."
Show: click the severity filter, then open one finding's detail.
Mention on screen (not spoken, or one line): real scans are disabled
on this public demo — POST /api/scans returns 403 — so nobody can
point it at an arbitrary target. The demo endpoint is the only scan
that runs here.

### 1:35–2:05 — History + safety (30 s)
On screen: History list, reopen a past scan.
Say: "Every scan is saved — target, finding counts, duration — and you
can reopen any of them. Real scans need the authorisation checkbox, a
valid domain only, no localhost or private IPs, one scan at a time,
and no active exploitation."
Show: history row → reopened scan with its findings.

### 2:05–2:40 — Built with Kiro (35 s)
On screen: repo https://github.com/Dungkrawww/hauntscan — show the
`.kiro/` folder at the root, then the spec files.
Say: "HauntScan was built spec-first with Kiro: the spec, steering and
hooks live in .kiro at the repo root. Nine tasks, from the SQLite store
to the FastAPI + SSE API to this dashboard — 74 tests passing."
Close on screen: app URL + repo URL + "Costume Contest — Kiroween 2026".

## Devpost write-up outline (fill in, do not invent)

- **What it does:** one dashboard for authorised web recon — discovery →
  probing → Nuclei DAST — with live SSE progress and severity triage.
- **How Kiro was used:** spec-driven development; `.kiro/specs/`,
  steering and hooks at repo root; tasks 1–9 implemented against the
  spec. Be honest in the write-up about what Kiro did vs what Muse did
  following the spec while the Kiro model registry was down — judges
  score Kiro usage depth, so describe the spec workflow concretely
  (requirements → design → tasks) rather than claiming CLI runs that
  did not happen.
- **Links:** live app https://hauntscan.onrender.com, repo
  https://github.com/Dungkrawww/hauntscan, video (YouTube link once
  uploaded, must be <3 min).
- **Tech:** Python 3.12, FastAPI, SQLite, plain HTML/CSS/JS frontend,
  NucleiFuzzer toolchain (`nf`) for real scans; demo-only guard
  (`HAUNTSCAN_DEMO_ONLY=1`) on the public deployment.
- **Safety note for judges:** public deployment runs demo scans only.

## Still open (not in this draft)

- Auto-deploy proof: Render GitHub App was connected ~10:56 WIB
  (auto-deploy "On Commit", PR Previews "Automatic") — functional
  proof is still pending until the next push to main or the next PR.
  The next push (e.g. adding this script to the repo, if the user
  wants it there) doubles as that proof; check the Render dashboard
  after it.
- Kiro 4,000-credit request: submitted 14 Nov, review within 48
  business hours; redeem by 4 Dec.
