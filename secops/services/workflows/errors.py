from __future__ import annotations

from dataclasses import dataclass

from secops.services.workflows.types import RetryClass


@dataclass(slots=True)
class WorkflowError(Exception):
    message: str
    retry_class: RetryClass = RetryClass.PERMANENT
    details: dict | None = None

    def __str__(self) -> str:
        return self.message


class WorkflowTransientError(WorkflowError):
    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message=message, retry_class=RetryClass.TRANSIENT, details=details)


class WorkflowBlockedError(WorkflowError):
    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message=message, retry_class=RetryClass.BLOCKED, details=details)


class WorkflowValidationError(WorkflowError):
    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message=message, retry_class=RetryClass.VALIDATION, details=details)


class WorkflowPermanentError(WorkflowError):
    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message=message, retry_class=RetryClass.PERMANENT, details=details)
