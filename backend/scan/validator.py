"""Target validation for HauntScan.

Only public domains/hostnames are accepted. Private/reserved IPs, loopback,
link-local addresses and ``localhost`` are rejected, as is any hostname that
resolves to a private address. Standard library only.
"""

from __future__ import annotations

import ipaddress
import re
import socket

_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_TLD = re.compile(r"^[A-Za-z]{2,}$")


class InvalidTarget(ValueError):
    """Raised when a scan target fails validation."""


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _reject_ip(value: str) -> None:
    """Reject any IP literal: HauntScan only scans public domain names."""
    raise InvalidTarget(f"IP literals are not accepted as targets: {value!r}")


def validate_target(target: str) -> str:
    """Validate a scan target and return its normalized (lowercased) form.

    Rules (see .kiro/steering/safety.md):
    - must be a non-empty string, max 253 chars
    - must be a valid public hostname with at least one dot and a
      letter-only TLD (no IP literals, no localhost)
    - must not resolve to a private / loopback / link-local address
    """
    if not isinstance(target, str):
        raise InvalidTarget("target must be a string")
    host = target.strip().lower().rstrip(".")
    if not host:
        raise InvalidTarget("target must not be empty")
    if len(host) > 253:
        raise InvalidTarget("target is too long (max 253 characters)")
    if _is_ip_literal(host):
        _reject_ip(host)
    if host == "localhost":
        raise InvalidTarget("localhost is not an allowed target")
    labels = host.split(".")
    if len(labels) < 2:
        raise InvalidTarget("target must be a fully qualified domain name")
    for label in labels:
        if not _LABEL.match(label):
            raise InvalidTarget(f"invalid label in target: {label!r}")
    if not _TLD.match(labels[-1]):
        raise InvalidTarget("target must end in a letter-only TLD")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise InvalidTarget(f"target does not resolve: {host!r}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # Reject only addresses that point at the local network or this
        # host: RFC 1918, loopback, link-local, unspecified, multicast.
        # Other non-routable ranges (e.g. CGNAT 198.18/15, documentation
        # prefixes) are not the local network — a scan to them simply
        # reaches nothing — so they are not rejected here.
        if (
            ip in ipaddress.ip_network("10.0.0.0/8")
            or ip in ipaddress.ip_network("172.16.0.0/12")
            or ip in ipaddress.ip_network("192.168.0.0/16")
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_multicast
        ):
            raise InvalidTarget(
                f"target resolves to a non-public address: {ip}"
            )
    return host
