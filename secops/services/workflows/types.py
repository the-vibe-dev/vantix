from __future__ import annotations

from enum import StrEnum
from typing import Any, TypedDict


class WorkflowStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    BLOCKED = "blocked"
    FAILED = "failed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class PhaseStatus(StrEnum):
    WAITING = "waiting"
    PENDING = "pending"
    CLAIMED = "claimed"
    RUNNING = "running"
    RETRYING = "retrying"
    BLOCKED = "blocked"
    FAILED = "failed"
    COMPLETED = "completed"
    SKIPPED = "skipped"


class RetryClass(StrEnum):
    NONE = "none"
    TRANSIENT = "transient"
    BLOCKED = "blocked"
    VALIDATION = "validation"
    PERMANENT = "permanent"
    OPERATOR_ACTION_REQUIRED = "operator-action-required"


class WorkerLeaseState(StrEnum):
    ACTIVE = "active"
    RELEASED = "released"
    EXPIRED = "expired"
    ABANDONED = "abandoned"


class CheckpointPayload(TypedDict, total=False):
    run_id: str
    workflow_id: str
    phase_name: str
    phase_attempt: int
    status: str
    output: dict[str, Any]
    metadata: dict[str, Any]
    resume_hint: str
