from __future__ import annotations

import os
import tempfile
from datetime import timedelta
from pathlib import Path

from sqlalchemy.orm import Session

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_retry_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, WorkflowExecution, WorkflowPhaseRun, WorkspaceRun
from secops.services.workflows.engine import WorkflowEngine, utcnow
from secops.services.workflows.phases import PHASE_SEQUENCE
from secops.services.workflows.types import PhaseStatus, WorkflowStatus


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed_run(db: Session) -> WorkspaceRun:
    engagement = Engagement(name="Retry Test", mode="ctf", target="10.10.10.10", tags=["ctf"])
    db.add(engagement)
    db.flush()
    run = WorkspaceRun(
        engagement_id=engagement.id,
        mode=engagement.mode,
        workspace_id="ctf-retry-test",
        status="planned",
        objective="retry flow",
        target="10.10.10.10",
        config_json={"ports": [], "services": [], "tags": ["ctf", "vantix"]},
    )
    db.add(run)
    db.flush()
    return run


def test_claim_complete_advances_to_next_phase() -> None:
    reset_db()
    engine_service = WorkflowEngine()
    with SessionLocal() as db:
        run = _seed_run(db)
        workflow = engine_service.enqueue_run(db, run)
        db.commit()
        db.refresh(workflow)

        claim = engine_service.claim_next_phase(db, worker_id="worker-a", lease_seconds=30)
        assert claim is not None
        assert claim.phase_name == PHASE_SEQUENCE[0]
        engine_service.mark_phase_completed(db, claim, output={"ok": True})
        db.commit()

        wf = db.get(WorkflowExecution, workflow.id)
        assert wf is not None
        assert wf.status == WorkflowStatus.RUNNING.value
        assert wf.current_phase == PHASE_SEQUENCE[1]
        next_row = (
            db.query(WorkflowPhaseRun)
            .filter(WorkflowPhaseRun.workflow_id == workflow.id, WorkflowPhaseRun.phase_name == PHASE_SEQUENCE[1])
            .first()
        )
        assert next_row is not None
        assert next_row.status == PhaseStatus.PENDING.value


def test_stale_claim_can_be_recovered_by_other_worker() -> None:
    reset_db()
    engine_service = WorkflowEngine()
    with SessionLocal() as db:
        run = _seed_run(db)
        workflow = engine_service.enqueue_run(db, run)
        db.commit()

        claim = engine_service.claim_next_phase(db, worker_id="worker-a", lease_seconds=30)
        assert claim is not None
        phase_run = db.get(WorkflowPhaseRun, claim.phase_run_id)
        assert phase_run is not None
        phase_run.status = PhaseStatus.CLAIMED.value
        phase_run.lease_expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

        recovered = engine_service.claim_next_phase(db, worker_id="worker-b", lease_seconds=30)
        assert recovered is not None
        assert recovered.phase_run_id == claim.phase_run_id
        assert recovered.worker_id == "worker-b"
