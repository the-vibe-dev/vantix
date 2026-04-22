"""Per-adapter transient/terminal error classification.

Adapters (nmap, CVE API, browser/Playwright, HTTP clients) raise a soup of
exception types. The workflow engine needs a single answer per exception:
retry as transient, fail permanently, or escalate as validation/blocked.

``classify_adapter_error(adapter, exc)`` returns a ``RetryDecision`` that
the engine feeds directly into ``schedule_retry`` / ``mark_phase_failed``.

Classification is intentionally conservative:
- Network-ish signals (timeouts, connection resets, DNS, 5xx, 429) →
  TRANSIENT with a per-adapter backoff hint.
- Structural failures (binary missing, 4xx other than 408/429, parse errors,
  explicit refusals) → PERMANENT.
- Adapter-specific known terminals (nmap "host seems down", CVE API auth
  failure) short-circuit to PERMANENT before the generic heuristic runs.
"""
from __future__ import annotations

import errno
import socket
from dataclasses import dataclass

from secops.services.workflows.types import RetryClass


@dataclass(slots=True)
class RetryDecision:
    retry_class: RetryClass
    retryable: bool
    delay_seconds: int = 0
    reason: str = ""


_DEFAULT_TRANSIENT_DELAY = {
    "nmap": 10,
    "cve": 30,
    "cve_api": 30,
    "browser": 5,
    "http": 5,
    "default": 10,
}


_TRANSIENT_NAME_SUBSTR = (
    "timeout",
    "timedout",
    "connectionerror",
    "connectionreseterror",
    "connectionabortederror",
    "connectionrefusederror",
    "remotedisconnected",
    "incompleteread",
    "readerror",
    "writeerror",
    "readtimeout",
    "connecterror",
    "playwrighttimeouterror",
    "targetclosederror",
    "networkerror",
)


_PERMANENT_NAME_SUBSTR = (
    "filenotfounderror",
    "permissionerror",
    "notadirectoryerror",
    "isadirectoryerror",
    "importerror",
    "modulenotfounderror",
    "syntaxerror",
    "valueerror",
    "typeerror",
    "keyerror",
    "attributeerror",
    "unicodeerror",
    "jsondecodeerror",
    "xml",
)


_TRANSIENT_OS_ERRNOS = {
    errno.EAGAIN,
    errno.EWOULDBLOCK,
    errno.ETIMEDOUT,
    errno.ECONNRESET,
    errno.ECONNABORTED,
    errno.ECONNREFUSED,
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.ENETRESET,
    errno.EPIPE,
}


def _message(exc: BaseException) -> str:
    try:
        return str(exc) or exc.__class__.__name__
    except Exception:  # noqa: BLE001
        return exc.__class__.__name__


def _extract_http_status(exc: BaseException) -> int | None:
    """Best-effort HTTP status pull — works for httpx, requests, urllib."""
    for attr in ("status_code", "status", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int) and 100 <= value <= 599:
            return value
    response = getattr(exc, "response", None)
    if response is not None:
        for attr in ("status_code", "status", "code"):
            value = getattr(response, attr, None)
            if isinstance(value, int) and 100 <= value <= 599:
                return value
    return None


def _adapter_delay(adapter: str) -> int:
    return _DEFAULT_TRANSIENT_DELAY.get((adapter or "").lower(), _DEFAULT_TRANSIENT_DELAY["default"])


def _transient(adapter: str, reason: str) -> RetryDecision:
    return RetryDecision(
        retry_class=RetryClass.TRANSIENT,
        retryable=True,
        delay_seconds=_adapter_delay(adapter),
        reason=reason,
    )


def _permanent(reason: str) -> RetryDecision:
    return RetryDecision(
        retry_class=RetryClass.PERMANENT,
        retryable=False,
        reason=reason,
    )


def _validation(reason: str) -> RetryDecision:
    return RetryDecision(
        retry_class=RetryClass.VALIDATION,
        retryable=False,
        reason=reason,
    )


def _classify_http_status(adapter: str, status: int) -> RetryDecision:
    if status in {408, 425, 429}:
        return _transient(adapter, f"retryable http {status}")
    if 500 <= status < 600:
        return _transient(adapter, f"upstream http {status}")
    if 400 <= status < 500:
        return _permanent(f"client http {status}")
    # Any other status that got turned into an error
    return _permanent(f"http {status}")


def _classify_nmap(exc: BaseException) -> RetryDecision | None:
    msg = _message(exc).lower()
    if "host seems down" in msg or "failed to resolve" in msg:
        return _permanent(f"nmap terminal: {msg[:120]}")
    if "could not open" in msg and "privileges" in msg:
        return _permanent(f"nmap privilege: {msg[:120]}")
    return None


def _classify_cve(exc: BaseException) -> RetryDecision | None:
    msg = _message(exc).lower()
    if "401" in msg or "unauthorized" in msg or "forbidden" in msg or "403" in msg:
        return _permanent(f"cve auth: {msg[:120]}")
    if "rate limit" in msg or "too many requests" in msg:
        return _transient("cve", "cve rate limit")
    return None


def _classify_browser(exc: BaseException) -> RetryDecision | None:
    msg = _message(exc).lower()
    name = exc.__class__.__name__.lower()
    if "browser has been closed" in msg or "target closed" in msg:
        return _transient("browser", "browser target closed")
    if "executable doesn't exist" in msg or "browsertype.launch" in msg:
        return _permanent(f"browser missing: {msg[:120]}")
    if "playwrighttimeout" in name or "timeouterror" in name:
        return _transient("browser", "browser timeout")
    return None


def classify_adapter_error(adapter: str, exc: BaseException) -> RetryDecision:
    """Map ``exc`` raised by ``adapter`` into a RetryDecision.

    ``adapter`` is a free-form lower-cased hint (``"nmap"``, ``"cve"``,
    ``"browser"``, ``"http"``). Unknown adapters fall through to the generic
    heuristic.
    """
    adapter = (adapter or "").lower()

    # Adapter-specific terminals first.
    specific = None
    if adapter == "nmap":
        specific = _classify_nmap(exc)
    elif adapter in {"cve", "cve_api"}:
        specific = _classify_cve(exc)
    elif adapter == "browser":
        specific = _classify_browser(exc)
    if specific is not None:
        return specific

    # HTTP status check (for httpx/requests wrapped errors).
    status = _extract_http_status(exc)
    if status is not None:
        return _classify_http_status(adapter, status)

    # OS-level errno on socket/OSError paths.
    if isinstance(exc, OSError) and exc.errno in _TRANSIENT_OS_ERRNOS:
        return _transient(adapter, f"os errno {exc.errno}")

    if isinstance(exc, socket.gaierror):
        return _transient(adapter, "dns resolution failed")

    if isinstance(exc, (TimeoutError, socket.timeout)):
        return _transient(adapter, "timeout")

    name = exc.__class__.__name__.lower()
    msg_lower = _message(exc).lower()

    # Substring match on class name — covers vendor-specific subclasses.
    if any(token in name for token in _TRANSIENT_NAME_SUBSTR):
        return _transient(adapter, f"transient {exc.__class__.__name__}")

    if any(token in name for token in _PERMANENT_NAME_SUBSTR):
        return _permanent(f"permanent {exc.__class__.__name__}")

    if "timed out" in msg_lower or "timeout" in msg_lower:
        return _transient(adapter, "message timeout")

    if "refused" in msg_lower or "reset" in msg_lower:
        return _transient(adapter, "connection disturbed")

    # Default: treat unknown exceptions conservatively as permanent so we
    # don't spin on bugs. Transient signal must be explicit.
    return _permanent(f"unclassified {exc.__class__.__name__}")
