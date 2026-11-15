"""Nuclei JSONL output parser for HauntScan.

One nuclei ``-jsonl`` line looks like::

    {"template-id": "http/missing-security-headers",
     "info": {"name": "...", "severity": "info",
              "description": "...", "tags": ["misc"]},
     "matched-at": "https://example.com", ...}

Malformed lines return ``None`` — they are counted, never crash a scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    template_id: str
    name: str
    severity: str
    matched_url: str
    description: str = ""
    tags: list[str] = field(default_factory=list)


def parse_line(line: str) -> Finding | None:
    """Parse one nuclei JSONL line into a Finding, or None if malformed."""
    if not line or not line.strip():
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    template_id = data.get("template-id")
    info = data.get("info")
    matched = data.get("matched-at") or data.get("host") or ""
    if not template_id or not isinstance(info, dict) or not matched:
        return None
    severity = str(info.get("severity", "unknown")).lower()
    if severity not in SEVERITIES:
        severity = "unknown"
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return Finding(
        template_id=str(template_id),
        name=str(info.get("name") or template_id),
        severity=severity,
        matched_url=str(matched),
        description=str(info.get("description") or ""),
        tags=[str(t) for t in tags if t],
    )


def parse_lines(lines) -> tuple[list[Finding], int]:
    """Parse many lines. Returns (findings, malformed_count)."""
    findings: list[Finding] = []
    malformed = 0
    for line in lines:
        finding = parse_line(line)
        if finding is None:
            malformed += 1
        else:
            findings.append(finding)
    return findings, malformed
