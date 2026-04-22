"""P1-2 — per-adapter transient/terminal error classifier."""
from __future__ import annotations

import errno
import socket

import pytest

from secops.services.workflows.adapter_errors import classify_adapter_error
from secops.services.workflows.types import RetryClass


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _FakeHttpError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"http {status}")
        self.status_code = status
        self.response = _FakeResponse(status)


class _FakePlaywrightTimeoutError(Exception):
    pass


class _FakeReadTimeout(Exception):
    pass


@pytest.mark.parametrize(
    "adapter,exc,expected_class,retryable",
    [
        ("http", TimeoutError("slow"), RetryClass.TRANSIENT, True),
        ("http", socket.timeout("slow"), RetryClass.TRANSIENT, True),
        ("http", _FakeReadTimeout("ReadTimeout: upstream slow"), RetryClass.TRANSIENT, True),
        ("http", socket.gaierror(-2, "dns"), RetryClass.TRANSIENT, True),
        ("http", _FakeHttpError(503), RetryClass.TRANSIENT, True),
        ("http", _FakeHttpError(429), RetryClass.TRANSIENT, True),
        ("http", _FakeHttpError(404), RetryClass.PERMANENT, False),
        ("http", _FakeHttpError(400), RetryClass.PERMANENT, False),
        ("http", ValueError("bad json"), RetryClass.PERMANENT, False),
        ("http", FileNotFoundError("no such"), RetryClass.PERMANENT, False),
    ],
)
def test_http_adapter_classification(adapter, exc, expected_class, retryable):
    decision = classify_adapter_error(adapter, exc)
    assert decision.retry_class == expected_class
    assert decision.retryable is retryable


def test_os_errno_transient():
    exc = OSError(errno.ECONNRESET, "peer reset")
    decision = classify_adapter_error("http", exc)
    assert decision.retry_class == RetryClass.TRANSIENT
    assert decision.retryable is True


def test_os_errno_permanent():
    exc = OSError(errno.EACCES, "permission denied")
    decision = classify_adapter_error("http", exc)
    # Not in the transient errno set → falls through to name heuristic (OSError
    # is not in either substr list), then to default PERMANENT.
    assert decision.retry_class == RetryClass.PERMANENT


def test_nmap_host_down_is_permanent():
    decision = classify_adapter_error("nmap", RuntimeError("Note: Host seems down."))
    assert decision.retry_class == RetryClass.PERMANENT
    assert "nmap terminal" in decision.reason


def test_nmap_generic_timeout_is_transient():
    decision = classify_adapter_error("nmap", TimeoutError("scan timed out"))
    assert decision.retry_class == RetryClass.TRANSIENT
    assert decision.delay_seconds == 10


def test_cve_api_auth_is_permanent():
    decision = classify_adapter_error("cve", RuntimeError("HTTP 401 Unauthorized from NVD"))
    assert decision.retry_class == RetryClass.PERMANENT


def test_cve_api_rate_limit_is_transient():
    decision = classify_adapter_error("cve", RuntimeError("rate limit exceeded, retry later"))
    assert decision.retry_class == RetryClass.TRANSIENT
    assert decision.delay_seconds == 30


def test_browser_target_closed_is_transient():
    decision = classify_adapter_error("browser", RuntimeError("Target closed"))
    assert decision.retry_class == RetryClass.TRANSIENT


def test_browser_missing_binary_is_permanent():
    decision = classify_adapter_error("browser", RuntimeError("Executable doesn't exist at /opt/chrome"))
    assert decision.retry_class == RetryClass.PERMANENT


def test_browser_playwright_timeout_subclass_is_transient():
    decision = classify_adapter_error("browser", _FakePlaywrightTimeoutError("element not visible"))
    assert decision.retry_class == RetryClass.TRANSIENT


def test_unknown_exception_defaults_to_permanent():
    class OddError(Exception):
        pass

    decision = classify_adapter_error("unknown", OddError("mystery"))
    assert decision.retry_class == RetryClass.PERMANENT


def test_adapter_specific_delay_differs():
    nmap_delay = classify_adapter_error("nmap", TimeoutError()).delay_seconds
    cve_delay = classify_adapter_error("cve", RuntimeError("rate limit")).delay_seconds
    browser_delay = classify_adapter_error("browser", _FakePlaywrightTimeoutError()).delay_seconds
    assert {nmap_delay, cve_delay, browser_delay} == {10, 30, 5}
