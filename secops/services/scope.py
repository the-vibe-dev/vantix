"""Target scope enforcement.

Resolves a user-supplied target (hostname/URL/IP/CIDR) against engagement
allowlists and a default deny-list of private / link-local / metadata ranges.

Public entry points:
    - normalize_target(raw): str -> hostname/ip without scheme or port
    - is_scope_allowed(target, *, allowed, excludes, allow_private): bool, reason

Kept as a pure module (no DB) so it's trivial to unit-test.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

# Deny-list for public-only scope (override per-engagement via allow_private=True).
_DEFAULT_DENY_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),   # carrier NAT
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),     # multicast
    ipaddress.ip_network("240.0.0.0/4"),     # reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),        # unique local
    ipaddress.ip_network("fe80::/10"),       # link-local v6
]

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-._]+(?<!-)$")


@dataclass(slots=True)
class ScopeVerdict:
    allowed: bool
    reason: str
    resolved: str = ""


def normalize_target(raw: str) -> str:
    """Extract host/ip from a URL, host:port, or bare host/ip."""
    if not raw:
        return ""
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.hostname:
            return parsed.hostname
    if raw.count(":") == 1 and not raw.startswith("["):
        host, _, _ = raw.partition(":")
        return host
    if raw.startswith("[") and "]" in raw:
        return raw[1 : raw.index("]")]
    return raw


def _ip_or_none(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _network_or_none(value: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _host_in_networks(ip: ipaddress._BaseAddress, networks: Iterable[ipaddress._BaseNetwork]) -> bool:
    return any(ip in net for net in networks)


def is_scope_allowed(
    target: str,
    *,
    allowed: Iterable[str] | None = None,
    excludes: Iterable[str] | None = None,
    allow_private: bool = False,
) -> ScopeVerdict:
    """Evaluate whether ``target`` is in scope.

    - ``allowed``: engagement allowlist (hostnames, IPs, CIDRs). Empty => deny.
    - ``excludes``: engagement blocklist (wins over allowlist).
    - ``allow_private``: if False, private/link-local/metadata ranges are denied
      regardless of allowlist.
    """
    normalized = normalize_target(target)
    if not normalized:
        return ScopeVerdict(False, "empty target")

    ip = _ip_or_none(normalized)

    # Default deny-list (unless engagement opts in).
    if ip is not None and not allow_private and _host_in_networks(ip, _DEFAULT_DENY_NETWORKS):
        return ScopeVerdict(False, f"{ip} is in a denied range (private/link-local/metadata)", resolved=str(ip))

    # Excludes win over allows.
    if excludes:
        for rule in excludes:
            if _match(rule, normalized, ip):
                return ScopeVerdict(False, f"{normalized} matches exclude rule {rule!r}", resolved=normalized)

    allowed_list = list(allowed or [])
    if not allowed_list:
        return ScopeVerdict(False, "engagement has no scope allowlist configured", resolved=normalized)

    for rule in allowed_list:
        if _match(rule, normalized, ip):
            return ScopeVerdict(True, f"matched allow rule {rule!r}", resolved=normalized)

    return ScopeVerdict(False, f"{normalized} is not covered by engagement allowlist", resolved=normalized)


def _match(rule: str, target: str, target_ip: ipaddress._BaseAddress | None) -> bool:
    rule = rule.strip()
    if not rule:
        return False
    # CIDR / IP rule
    net = _network_or_none(rule)
    if net is not None and target_ip is not None:
        if target_ip in net:
            return True
    # Exact host or suffix match (e.g., ".example.com")
    if rule.startswith(".") and target.endswith(rule):
        return True
    if target == rule:
        return True
    if _HOSTNAME_RE.match(rule) and target.lower() == rule.lower():
        return True
    return False
