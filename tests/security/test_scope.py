"""PRA-002 regression: engagement scope enforcement."""
from __future__ import annotations

from secops.services.scope import is_scope_allowed, normalize_target


def test_empty_target_denied() -> None:
    verdict = is_scope_allowed("", allowed=["10.0.0.1"])
    assert verdict.allowed is False


def test_empty_allowlist_denied_even_on_match() -> None:
    verdict = is_scope_allowed("10.0.0.1", allowed=[])
    assert verdict.allowed is False


def test_private_denied_by_default() -> None:
    verdict = is_scope_allowed("10.0.0.1", allowed=["10.0.0.0/8"], allow_private=False)
    assert verdict.allowed is False
    assert "denied range" in verdict.reason


def test_private_allowed_when_explicitly_opted_in() -> None:
    verdict = is_scope_allowed("10.0.0.1", allowed=["10.0.0.0/8"], allow_private=True)
    assert verdict.allowed is True


def test_link_local_metadata_always_denied_by_default() -> None:
    verdict = is_scope_allowed("169.254.169.254", allowed=["169.254.0.0/16"], allow_private=False)
    assert verdict.allowed is False


def test_localhost_denied_by_default() -> None:
    verdict = is_scope_allowed("127.0.0.1", allowed=["127.0.0.0/8"], allow_private=False)
    assert verdict.allowed is False


def test_cidr_allow_rule_matches_public_ip() -> None:
    verdict = is_scope_allowed("203.0.113.5", allowed=["203.0.113.0/24"])
    assert verdict.allowed is True


def test_exact_hostname_allow_rule() -> None:
    verdict = is_scope_allowed("target.example.com", allowed=["target.example.com"])
    assert verdict.allowed is True


def test_suffix_allow_rule_matches_subdomain() -> None:
    verdict = is_scope_allowed("api.target.example.com", allowed=[".example.com"])
    assert verdict.allowed is True


def test_excludes_override_allow() -> None:
    verdict = is_scope_allowed(
        "api.example.com",
        allowed=[".example.com"],
        excludes=["api.example.com"],
    )
    assert verdict.allowed is False


def test_hostname_not_in_allow_denied() -> None:
    verdict = is_scope_allowed("evil.example.org", allowed=["target.example.com"])
    assert verdict.allowed is False


def test_url_is_normalized_to_host() -> None:
    assert normalize_target("https://target.example.com:8443/path") == "target.example.com"


def test_host_port_normalized() -> None:
    assert normalize_target("target.example.com:443") == "target.example.com"


def test_ipv6_bracketed_normalized() -> None:
    assert normalize_target("[2001:db8::1]:443") == "2001:db8::1"
