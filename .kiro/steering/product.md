# Product: HauntScan

## What it is

HauntScan is a web dashboard that runs authorized web-recon scans and shows results live. The user enters a target domain, confirms authorization, and the app runs a recon pipeline (URL/subdomain discovery → live-host probing → Nuclei DAST scan), streams progress, and presents findings grouped by severity.

## Who it is for

Beginner bug bounty hunters who know the recon tools exist but find the terminal workflow painful. They want one place to run a scan and triage what came back.

## MVP scope

1. **New scan** — form with target domain, authorization checkbox, and scan profile (Quick / Full). Validates domain/hostname; rejects private IPs and localhost.
2. **Live progress** — scan runs as a background job; UI streams log lines and a progress bar.
3. **Findings** — table of findings with severity (critical / high / medium / low / info), template name, matched URL, description; filter by severity; click for detail.
4. **History** — list of past scans with status, target, finding counts, duration; reopen any scan.
5. **Demo mode** — canned scan result from a fixture file; works with no network.
6. **Safety controls** — authorization checkbox required; 1 concurrent scan; scan timeout; every scan logged with target and timestamp.

## Non-goals for MVP

- User accounts or login (single-user local app).
- Scheduled or recurring scans.
- Auto-exploitation or payload validation.
- Multi-target bulk scanning.

## UI theme

Haunted house / ghost hunt: dark background, eerie green + pumpkin orange + ghost-purple accents, subtle fog and ghost motifs, playful copy ("Scan the darkness", "Something is hiding here"). The theme enhances function — severity must stay readable at a glance and the scan log must stay legible.
