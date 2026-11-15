"""Tests for backend.scan.validator."""

import pytest

from backend.scan.validator import InvalidTarget, validate_target


@pytest.mark.parametrize(
    "host",
    ["example.com", "sub.example.co.id", "EXAMPLE.COM", "a-b.example.org"],
)
def test_valid_domains_accepted(host):
    assert validate_target(host) == host.strip().lower()


def test_trailing_dot_and_whitespace_stripped():
    assert validate_target("  example.com. ") == "example.com"


@pytest.mark.parametrize(
    "host",
    [
        "192.168.1.1",
        "10.0.0.5",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "8.8.8.8",
        "::1",
    ],
)
def test_ip_literals_rejected(host):
    with pytest.raises(InvalidTarget):
        validate_target(host)


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST"])
def test_localhost_rejected(host):
    with pytest.raises(InvalidTarget):
        validate_target(host)


@pytest.mark.parametrize(
    "host",
    ["", "   ", "example", "exa mple.com", "-bad.example.com",
     "bad-.example.com", "example.c0m", "a" * 254 + ".com"],
)
def test_malformed_rejected(host):
    with pytest.raises(InvalidTarget):
        validate_target(host)


def test_unresolvable_rejected(monkeypatch):
    # The sandbox DNS answers every name, so simulate NXDOMAIN instead.
    def _raise(*args, **kwargs):
        import socket

        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr("socket.getaddrinfo", _raise)
    with pytest.raises(InvalidTarget):
        validate_target("this-domain-definitely-does-not-exist-12345.com")
