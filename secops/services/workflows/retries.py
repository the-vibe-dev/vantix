from __future__ import annotations

from dataclasses import dataclass

from secops.services.workflows.types import RetryClass


@dataclass(slots=True)
class RetryDecision:
    retry_class: RetryClass
    retryable: bool
    delay_seconds: int = 0
    reason: str = ""


def classify_retry(error_class: str) -> RetryDecision:
    key = (error_class or "").lower()
    if key in {"transient", "timeout", "io", "network"}:
        return RetryDecision(retry_class=RetryClass.TRANSIENT, retryable=True, delay_seconds=15, reason="transient failure")
    if key in {"blocked", "approval"}:
        return RetryDecision(retry_class=RetryClass.BLOCKED, retryable=False, reason="blocked until operator action")
    if key in {"validation"}:
        return RetryDecision(retry_class=RetryClass.VALIDATION, retryable=False, reason="validation error")
    return RetryDecision(retry_class=RetryClass.PERMANENT, retryable=False, reason="permanent failure")
