"""PRA-011 regression: subprocess output redaction covers common secret types."""
from __future__ import annotations

import pytest

from secops.services.policies import ExecutionPolicyService


@pytest.fixture
def policy() -> ExecutionPolicyService:
    return ExecutionPolicyService()


def _redacted(policy: ExecutionPolicyService, text: str) -> str:
    return policy._redact(text)


@pytest.mark.parametrize(
    "label,sample",
    [
        ("openai", "OPENAI_KEY=sk-abcdefghijklmnop1234567890abcdef"),
        ("github_pat_classic", "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("github_fine_grained", "github_pat_11AAAAAAA0" + "X" * 60),
        ("github_oauth", "gho_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
        ("aws_access_key", "Access: AKIAABCDEFGHIJKLMNOP"),
        ("aws_temp", "ASIAABCDEFGHIJKLMNOP"),
        ("slack_bot_token", "xoxb-12345-67890-abcde"),
        ("jwt", "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload12345.signature-value"),
        ("bearer_header", "Authorization: Bearer abcdef1234567890"),
        ("basic_auth_header", "Authorization: Basic dXNlcjpwYXNzd29yZA=="),
        ("password_kv", "password: hunter2-very-strong"),
        ("userinfo_url", "https://user:secret-pass@db.example.com/path"),
        ("google_api", "key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"),
        ("gitlab_pat", "gl" + "pat-" + "abcdef12345ABCDEFGHI"),
        ("cookie_header", "Cookie: session=abc123; token=def456"),
        ("private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"),
    ],
)
def test_secret_patterns_are_redacted(policy: ExecutionPolicyService, label: str, sample: str) -> None:
    out = _redacted(policy, sample)
    assert "[REDACTED]" in out, f"{label}: no redaction applied"
    # The original secret body must not survive verbatim.
    if "PRIVATE KEY" in sample:
        assert "MIIEpAIBAAKCAQEA" not in out
    elif "Bearer" in sample:
        assert "abcdef1234567890" not in out


def test_output_truncated_beyond_16kb(policy: ExecutionPolicyService) -> None:
    big = "A" * (20 * 1024)
    out = _redacted(policy, big)
    assert "[TRUNCATED" in out
    assert len(out) < len(big)


def test_benign_output_unchanged(policy: ExecutionPolicyService) -> None:
    out = _redacted(policy, "nmap scan report: 80/tcp open http")
    assert out == "nmap scan report: 80/tcp open http"
