from __future__ import annotations

from sqlalchemy import update
from sqlalchemy.orm import Session

from secops.models import RunCheckpoint
from secops.services.workflows.types import CheckpointPayload


class CheckpointService:
    def save(
        self,
        db: Session,
        *,
        run_id: str,
        phase_name: str,
        payload: CheckpointPayload,
        workflow_id: str | None = None,
        phase_attempt: int = 1,
        checkpoint_key: str = "state",
        status: str = "ready",
    ) -> RunCheckpoint:
        db.execute(
            update(RunCheckpoint)
            .where(
                RunCheckpoint.run_id == run_id,
                RunCheckpoint.phase_name == phase_name,
                RunCheckpoint.checkpoint_key == checkpoint_key,
                RunCheckpoint.is_latest.is_(True),
            )
            .values(is_latest=False)
        )
        checkpoint = RunCheckpoint(
            run_id=run_id,
            workflow_id=workflow_id,
            phase_name=phase_name,
            phase_attempt=phase_attempt,
            checkpoint_key=checkpoint_key,
            status=status,
            payload_json=dict(payload),
            is_latest=True,
        )
        db.add(checkpoint)
        db.flush()
        return checkpoint

    def get_latest(self, db: Session, *, run_id: str, phase_name: str, checkpoint_key: str = "state") -> RunCheckpoint | None:
        return (
            db.query(RunCheckpoint)
            .filter(
                RunCheckpoint.run_id == run_id,
                RunCheckpoint.phase_name == phase_name,
                RunCheckpoint.checkpoint_key == checkpoint_key,
                RunCheckpoint.is_latest.is_(True),
            )
            .order_by(RunCheckpoint.updated_at.desc())
            .first()
        )
