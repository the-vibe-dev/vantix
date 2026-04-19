from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from secops.models import WorkerLease, WorkflowExecution, WorkflowPhaseRun, WorkspaceRun
from secops.services.workflows.phases import PHASE_SEQUENCE, next_phase
from secops.services.workflows.types import PhaseStatus, WorkerLeaseState, WorkflowStatus


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class WorkflowClaim:
    phase_run_id: str
    workflow_id: str
    run_id: str
    phase_name: str
    attempt: int
    lease_id: str
    worker_id: str
    lease_expires_at: datetime


class WorkflowEngine:
    def enqueue_run(self, db: Session, run: WorkspaceRun) -> WorkflowExecution:
        workflow = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.run_id == run.id)
            .order_by(WorkflowExecution.created_at.desc())
            .first()
        )
        if workflow is None:
            workflow = WorkflowExecution(
                run_id=run.id,
                workflow_kind="vantix-run",
                status=WorkflowStatus.QUEUED.value,
                current_phase=PHASE_SEQUENCE[0],
                started_at=utcnow(),
            )
            db.add(workflow)
            db.flush()
            for idx, phase_name in enumerate(PHASE_SEQUENCE):
                db.add(
                    WorkflowPhaseRun(
                        run_id=run.id,
                        workflow_id=workflow.id,
                        phase_name=phase_name,
                        attempt=1,
                        status=PhaseStatus.PENDING.value if idx == 0 else PhaseStatus.WAITING.value,
                        metadata_json={"phase_index": idx},
                    )
                )
            db.flush()
        else:
            if workflow.status in {WorkflowStatus.COMPLETED.value, WorkflowStatus.FAILED.value, WorkflowStatus.CANCELLED.value}:
                workflow.status = WorkflowStatus.QUEUED.value
                workflow.completed_at = None
            waiting = (
                db.query(WorkflowPhaseRun)
                .filter(
                    WorkflowPhaseRun.workflow_id == workflow.id,
                    WorkflowPhaseRun.status.in_([PhaseStatus.WAITING.value, PhaseStatus.BLOCKED.value]),
                )
                .order_by(WorkflowPhaseRun.created_at.asc())
                .first()
            )
            if waiting:
                waiting.status = PhaseStatus.PENDING.value
                workflow.current_phase = waiting.phase_name

        run.status = "queued"
        workflow.updated_at = utcnow()
        return workflow

    def claim_next_phase(self, db: Session, *, worker_id: str, lease_seconds: int = 90) -> WorkflowClaim | None:
        now = utcnow()
        candidate = (
            db.query(WorkflowPhaseRun)
            .join(WorkflowExecution, WorkflowExecution.id == WorkflowPhaseRun.workflow_id)
            .filter(
                WorkflowExecution.status.in_([WorkflowStatus.QUEUED.value, WorkflowStatus.RUNNING.value]),
                or_(
                    WorkflowPhaseRun.status.in_([PhaseStatus.PENDING.value, PhaseStatus.RETRYING.value]),
                    and_(
                        WorkflowPhaseRun.status == PhaseStatus.CLAIMED.value,
                        WorkflowPhaseRun.lease_expires_at.is_not(None),
                        WorkflowPhaseRun.lease_expires_at < now,
                    ),
                ),
                or_(WorkflowPhaseRun.next_attempt_at.is_(None), WorkflowPhaseRun.next_attempt_at <= now),
            )
            .order_by(WorkflowPhaseRun.created_at.asc())
            .first()
        )
        if candidate is None:
            return None

        lease_until = now + timedelta(seconds=lease_seconds)
        candidate.status = PhaseStatus.CLAIMED.value
        candidate.worker_id = worker_id
        candidate.lease_expires_at = lease_until
        candidate.started_at = candidate.started_at or now

        workflow = db.get(WorkflowExecution, candidate.workflow_id)
        if workflow is not None:
            workflow.status = WorkflowStatus.RUNNING.value
            workflow.current_phase = candidate.phase_name
            workflow.attempt_count = max(workflow.attempt_count, candidate.attempt)
            workflow.updated_at = now

        run = db.get(WorkspaceRun, candidate.run_id)
        if run is not None and run.status not in {"blocked", "cancelled", "failed"}:
            run.status = "running"
            run.updated_at = now

        lease = WorkerLease(
            run_id=candidate.run_id,
            workflow_id=candidate.workflow_id,
            phase_name=candidate.phase_name,
            phase_run_id=candidate.id,
            worker_id=worker_id,
            status=WorkerLeaseState.ACTIVE.value,
            heartbeat_at=now,
            lease_expires_at=lease_until,
            metadata_json={},
        )
        db.add(lease)
        db.flush()
        return WorkflowClaim(
            phase_run_id=candidate.id,
            workflow_id=candidate.workflow_id,
            run_id=candidate.run_id,
            phase_name=candidate.phase_name,
            attempt=candidate.attempt,
            lease_id=lease.id,
            worker_id=worker_id,
            lease_expires_at=lease_until,
        )

    def mark_phase_completed(self, db: Session, claim: WorkflowClaim, *, output: dict | None = None) -> None:
        now = utcnow()
        phase_run = db.get(WorkflowPhaseRun, claim.phase_run_id)
        if phase_run is None:
            return
        phase_run.status = PhaseStatus.COMPLETED.value
        phase_run.completed_at = now
        phase_run.lease_expires_at = now
        phase_run.output_json = output or phase_run.output_json

        lease = db.get(WorkerLease, claim.lease_id)
        if lease is not None:
            lease.status = WorkerLeaseState.RELEASED.value
            lease.released_at = now
            lease.heartbeat_at = now
            lease.lease_expires_at = now

        workflow = db.get(WorkflowExecution, claim.workflow_id)
        next_name = next_phase(claim.phase_name)
        if workflow is not None:
            if next_name is None:
                workflow.status = WorkflowStatus.COMPLETED.value
                workflow.current_phase = "completed"
                workflow.completed_at = now
            else:
                workflow.status = WorkflowStatus.RUNNING.value
                workflow.current_phase = next_name
                next_row = (
                    db.query(WorkflowPhaseRun)
                    .filter(
                        WorkflowPhaseRun.workflow_id == workflow.id,
                        WorkflowPhaseRun.phase_name == next_name,
                    )
                    .order_by(WorkflowPhaseRun.attempt.asc())
                    .first()
                )
                if next_row and next_row.status == PhaseStatus.WAITING.value:
                    next_row.status = PhaseStatus.PENDING.value
            workflow.updated_at = now

        run = db.get(WorkspaceRun, claim.run_id)
        if run is not None and workflow is not None:
            run.status = "completed" if workflow.status == WorkflowStatus.COMPLETED.value else "running"
            run.updated_at = now

    def mark_phase_failed(self, db: Session, claim: WorkflowClaim, *, error_class: str, error_message: str) -> None:
        now = utcnow()
        phase_run = db.get(WorkflowPhaseRun, claim.phase_run_id)
        if phase_run is None:
            return
        phase_run.status = PhaseStatus.FAILED.value
        phase_run.completed_at = now
        phase_run.lease_expires_at = now
        phase_run.error_json = {"class": error_class, "message": error_message}

        lease = db.get(WorkerLease, claim.lease_id)
        if lease is not None:
            lease.status = WorkerLeaseState.RELEASED.value
            lease.released_at = now
            lease.heartbeat_at = now
            lease.lease_expires_at = now

        workflow = db.get(WorkflowExecution, claim.workflow_id)
        if workflow is not None:
            workflow.status = WorkflowStatus.FAILED.value
            workflow.error_class = error_class
            workflow.blocked_reason = error_message[:255]
            workflow.updated_at = now
            workflow.completed_at = now

        run = db.get(WorkspaceRun, claim.run_id)
        if run is not None:
            run.status = "failed"
            run.updated_at = now

    def mark_phase_blocked(self, db: Session, claim: WorkflowClaim, *, reason: str) -> None:
        now = utcnow()
        phase_run = db.get(WorkflowPhaseRun, claim.phase_run_id)
        if phase_run is not None:
            phase_run.status = PhaseStatus.BLOCKED.value
            phase_run.completed_at = now
            phase_run.lease_expires_at = now
            phase_run.error_json = {"class": "blocked", "message": reason}

        lease = db.get(WorkerLease, claim.lease_id)
        if lease is not None:
            lease.status = WorkerLeaseState.RELEASED.value
            lease.released_at = now
            lease.heartbeat_at = now
            lease.lease_expires_at = now

        workflow = db.get(WorkflowExecution, claim.workflow_id)
        if workflow is not None:
            workflow.status = WorkflowStatus.BLOCKED.value
            workflow.blocked_reason = reason[:255]
            workflow.updated_at = now

        run = db.get(WorkspaceRun, claim.run_id)
        if run is not None:
            run.status = "blocked"
            run.updated_at = now

    def schedule_retry(
        self,
        db: Session,
        claim: WorkflowClaim,
        *,
        retry_class: str,
        delay_seconds: int,
        reason: str,
    ) -> WorkflowPhaseRun | None:
        now = utcnow()
        phase_run = db.get(WorkflowPhaseRun, claim.phase_run_id)
        if phase_run is None:
            return None

        phase_run.status = PhaseStatus.FAILED.value
        phase_run.completed_at = now
        phase_run.lease_expires_at = now
        phase_run.retry_class = retry_class
        phase_run.error_json = {"class": retry_class, "message": reason}

        lease = db.get(WorkerLease, claim.lease_id)
        if lease is not None:
            lease.status = WorkerLeaseState.RELEASED.value
            lease.released_at = now
            lease.heartbeat_at = now
            lease.lease_expires_at = now

        next_attempt = WorkflowPhaseRun(
            run_id=phase_run.run_id,
            workflow_id=phase_run.workflow_id,
            phase_name=phase_run.phase_name,
            attempt=phase_run.attempt + 1,
            status=PhaseStatus.RETRYING.value,
            retry_class=retry_class,
            next_attempt_at=now + timedelta(seconds=max(1, delay_seconds)),
            metadata_json={"retry_from_phase_run_id": phase_run.id},
        )
        db.add(next_attempt)
        db.flush()

        workflow = db.get(WorkflowExecution, phase_run.workflow_id)
        if workflow is not None:
            workflow.status = WorkflowStatus.RUNNING.value
            workflow.current_phase = phase_run.phase_name
            workflow.attempt_count = max(workflow.attempt_count, next_attempt.attempt)
            workflow.updated_at = now

        run = db.get(WorkspaceRun, phase_run.run_id)
        if run is not None and run.status not in {"cancelled", "blocked"}:
            run.status = "running"
            run.updated_at = now
        return next_attempt

    def block_run(self, db: Session, run: WorkspaceRun, reason: str) -> None:
        run.status = "blocked"
        run.updated_at = utcnow()
        workflow = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.run_id == run.id)
            .order_by(WorkflowExecution.created_at.desc())
            .first()
        )
        if workflow is not None:
            workflow.status = WorkflowStatus.BLOCKED.value
            workflow.blocked_reason = reason[:255]
            workflow.updated_at = utcnow()

    def cancel_run(self, db: Session, run: WorkspaceRun, reason: str = "cancelled") -> None:
        now = utcnow()
        run.status = "cancelled"
        run.updated_at = now
        workflow = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.run_id == run.id)
            .order_by(WorkflowExecution.created_at.desc())
            .first()
        )
        if workflow is not None:
            workflow.status = WorkflowStatus.CANCELLED.value
            workflow.blocked_reason = reason[:255]
            workflow.updated_at = now
            workflow.completed_at = now
