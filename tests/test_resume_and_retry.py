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
from secops.models import Engagement, WorkerLease, WorkerRuntimeStatus, WorkflowExecution, WorkflowPhaseRun, WorkspaceRun
from secops.services.workflows.engine import WorkflowClaim, WorkflowEngine, utcnow
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


def test_claim_owner_guard_and_lease_renewal() -> None:
    reset_db()
    engine_service = WorkflowEngine()
    with SessionLocal() as db:
        run = _seed_run(db)
        workflow = engine_service.enqueue_run(db, run)
        db.commit()

        claim = engine_service.claim_next_phase(db, worker_id="worker-a", lease_seconds=20)
        assert claim is not None
        assert engine_service.claim_next_phase(db, worker_id="worker-b", lease_seconds=20) is None
        prior_expiry = claim.lease_expires_at
        assert engine_service.renew_lease(db, claim, lease_seconds=90) is True
        db.commit()
        assert claim.lease_expires_at > prior_expiry

        forged = WorkflowClaim(
            phase_run_id=claim.phase_run_id,
            workflow_id=claim.workflow_id,
            run_id=claim.run_id,
            phase_name=claim.phase_name,
            attempt=claim.attempt,
            lease_id=claim.lease_id,
            worker_id="worker-b",
            lease_expires_at=claim.lease_expires_at,
        )
        engine_service.mark_phase_completed(db, forged, output={"forged": True})
        db.commit()
        phase_row = db.get(WorkflowPhaseRun, claim.phase_run_id)
        assert phase_row is not None
        assert phase_row.status == PhaseStatus.CLAIMED.value

        engine_service.mark_phase_completed(db, claim, output={"ok": True})
        db.commit()
        phase_row = db.get(WorkflowPhaseRun, claim.phase_run_id)
        assert phase_row is not None
        assert phase_row.status == PhaseStatus.COMPLETED.value
        wf = db.get(WorkflowExecution, workflow.id)
        assert wf is not None
        assert wf.current_phase == PHASE_SEQUENCE[1]


def test_scavenge_stale_runtime_recovers_claim_and_marks_worker_stale() -> None:
    reset_db()
    engine_service = WorkflowEngine()
    with SessionLocal() as db:
        run = _seed_run(db)
        workflow = engine_service.enqueue_run(db, run)
        db.commit()

        claim = engine_service.claim_next_phase(db, worker_id="worker-a", lease_seconds=20)
        assert claim is not None
        phase_row = db.get(WorkflowPhaseRun, claim.phase_run_id)
        assert phase_row is not None
        phase_row.lease_expires_at = utcnow() - timedelta(seconds=5)
        db.add(
            WorkerRuntimeStatus(
                worker_id="worker-a",
                hostname="localhost",
                pid=1234,
                status="running",
                current_run_id=run.id,
                current_phase=phase_row.phase_name,
                heartbeat_at=utcnow() - timedelta(seconds=600),
                metadata_json={},
            )
        )
        db.commit()

        summary = engine_service.scavenge_stale_runtime(db, stale_worker_after_seconds=60)
        db.commit()

        assert summary["recovered_claims"] == 1
        assert summary["stale_workers"] == 1

        db.refresh(phase_row)
        assert phase_row.status == PhaseStatus.RETRYING.value
        assert phase_row.worker_id == ""
        assert phase_row.retry_class == "transient"

        leases = db.query(WorkerLease).filter(WorkerLease.phase_run_id == phase_row.id).all()
        assert leases
        assert all(lease.status == "expired" for lease in leases)

        worker = db.query(WorkerRuntimeStatus).filter(WorkerRuntimeStatus.worker_id == "worker-a").first()
        assert worker is not None
        assert worker.status == "stale"
