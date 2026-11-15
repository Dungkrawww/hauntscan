"""Tests for backend.scan.parser."""

import json

import pytest

from backend.scan.parser import parse_line, parse_lines


def _line(**overrides):
    base = {
        "template-id": "http/missing-security-headers",
        "info": {
            "name": "Missing Security Headers",
            "severity": "info",
            "description": "Checks for missing headers.",
            "tags": ["misc", "headers"],
        },
        "matched-at": "https://example.com",
    }
    base.update(overrides)
    return json.dumps(base)


def test_valid_line_parsed():
    finding = parse_line(_line())
    assert finding is not None
    assert finding.template_id == "http/missing-security-headers"
    assert finding.name == "Missing Security Headers"
    assert finding.severity == "info"
    assert finding.matched_url == "https://example.com"
    assert finding.tags == ["misc", "headers"]


def test_severity_normalized_to_lowercase():
    finding = parse_line(_line(info={"name": "X", "severity": "HIGH"}))
    assert finding is not None
    assert finding.severity == "high"


def test_unknown_severity_falls_back():
    finding = parse_line(_line(info={"name": "X", "severity": "weird"}))
    assert finding is not None
    assert finding.severity == "unknown"


def test_matched_at_falls_back_to_host():
    finding = parse_line(_line(**{"matched-at": None, "host": "https://example.com"}))
    assert finding is not None
    assert finding.matched_url == "https://example.com"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "not json at all",
        '{"template-id": 123}',
        json.dumps({"info": {"severity": "high"}}),
        json.dumps({"template-id": "x"}),
        json.dumps(["not", "a", "dict"]),
        json.dumps(
            {"template-id": "x", "info": {"severity": "high"}}
        ),  # no matched-at/host
    ],
)
def test_malformed_lines_return_none(bad):
    assert parse_line(bad) is None


def test_parse_lines_counts_malformed():
    lines = [_line(), "garbage", _line(), ""]
    findings, malformed = parse_lines(lines)
    assert len(findings) == 2
    assert malformed == 2
