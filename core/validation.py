"""Shared domain validation helpers for all runtime variants."""

from __future__ import annotations

import ipaddress
import socket
import re
from dataclasses import dataclass

_HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+$")
_TLD_RE = re.compile(r"^[a-z]{2,63}$")

_BLOCKED_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.169.254/32"),  # Common cloud metadata
    ipaddress.ip_network("169.254.170.2/32"),    # ECS task metadata endpoint
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba metadata endpoint
]


@dataclass
class DomainValidationError(Exception):
    code: str
    message: str

    def to_dict(self):
        return {"error": self.message, "code": self.code}


def _raise_invalid(message: str):
    raise DomainValidationError("invalid_domain", message)


def _raise_blocked(message: str):
    raise DomainValidationError("blocked_target", message)


def validate_domain_input(raw_domain: str) -> str:
    """
    Validate and canonicalize user-provided domain input.
    Returns lowercased, punycoded hostname.
    """
    if not isinstance(raw_domain, str):
        _raise_invalid("domain must be a string")

    value = raw_domain.strip()
    if not value:
        _raise_invalid("domain is required")

    if any(c in value for c in ("/", "?", "#", "@", ":", "://")):
        _raise_invalid("hostname only; no scheme, path, query, port, or userinfo")

    if value.endswith("."):
        value = value[:-1]

    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError:
        _raise_invalid("invalid IDN/hostname encoding")

    canonical = ascii_domain.lower()

    if len(canonical) > 253:
        _raise_invalid("domain is too long")
    if "." not in canonical:
        _raise_invalid("hostname must include a valid TLD")
    if not _HOSTNAME_RE.match(canonical):
        _raise_invalid("hostname contains invalid characters")
    if ".." in canonical:
        _raise_invalid("hostname contains empty labels")

    labels = canonical.split(".")
    if any(not label for label in labels):
        _raise_invalid("hostname contains empty labels")
    if any(len(label) > 63 for label in labels):
        _raise_invalid("hostname label exceeds 63 characters")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        _raise_invalid("hostname labels cannot start/end with hyphen")

    tld = labels[-1]
    if not _TLD_RE.match(tld):
        _raise_invalid("invalid TLD format")

    _enforce_not_blocked_target(canonical)
    return canonical


def _enforce_not_blocked_target(domain: str):
    try:
        addrinfo = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return

    if not addrinfo:
        return

    checked_ips = set()
    for info in addrinfo:
        ip_raw = info[4][0]
        if ip_raw in checked_ips:
            continue
        checked_ips.add(ip_raw)

        try:
            ip = ipaddress.ip_address(ip_raw)
        except ValueError:
            continue

        if ip.is_private or ip.is_loopback or ip.is_link_local:
            _raise_blocked(f"target resolves to non-public IP ({ip})")
        if ip.is_unspecified or ip.is_reserved or ip.is_multicast:
            _raise_blocked(f"target resolves to blocked IP ({ip})")
        if any(ip in network for network in _BLOCKED_METADATA_NETWORKS):
            _raise_blocked(f"target resolves to blocked metadata IP ({ip})")

