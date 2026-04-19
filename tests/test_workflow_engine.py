from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_workflow_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, RunCheckpoint, RunMetric, WorkerLease, WorkflowExecution, WorkflowPhaseRun, WorkspaceRun
from secops.services.workflows.checkpoints import CheckpointService
from secops.services.workflows.types import PhaseStatus, RetryClass, WorkerLeaseState, WorkflowStatus


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_workflow_schema_and_checkpoint_latest_semantics() -> None:
    reset_db()
    with SessionLocal() as db:
        engagement = Engagement(name="Workflow Test", mode="pentest", target="10.10.10.10", tags=["pentest"])
        db.add(engagement)
        db.flush()
        run = WorkspaceRun(
            engagement_id=engagement.id,
            mode=engagement.mode,
            workspace_id="pentest-workflow-schema-test",
            status="planned",
            objective="Validate durable workflow schema",
            target="10.10.10.10",
            config_json={"ports": ["80"], "services": ["http"], "tags": ["pentest", "vantix"]},
        )
        db.add(run)
        db.flush()

        workflow = WorkflowExecution(
            run_id=run.id,
            workflow_kind="vantix-run",
            status=WorkflowStatus.QUEUED.value,
            current_phase="context-bootstrap",
        )
        db.add(workflow)
        db.flush()

        phase_1 = WorkflowPhaseRun(
            run_id=run.id,
            workflow_id=workflow.id,
            phase_name="context-bootstrap",
            attempt=1,
            status=PhaseStatus.COMPLETED.value,
            retry_class=RetryClass.NONE.value,
            output_json={"prompt_path": "/tmp/prompt1.txt"},
        )
        phase_2 = WorkflowPhaseRun(
            run_id=run.id,
            workflow_id=workflow.id,
            phase_name="context-bootstrap",
            attempt=2,
            status=PhaseStatus.COMPLETED.value,
            retry_class=RetryClass.TRANSIENT.value,
            output_json={"prompt_path": "/tmp/prompt2.txt"},
        )
        db.add(phase_1)
        db.add(phase_2)
        db.flush()

        checkpoints = CheckpointService()
        cp1 = checkpoints.save(
            db,
            run_id=run.id,
            workflow_id=workflow.id,
            phase_name="context-bootstrap",
            phase_attempt=1,
            payload={"phase_name": "context-bootstrap", "phase_attempt": 1, "output": {"prompt_path": "/tmp/prompt1.txt"}},
        )
        cp2 = checkpoints.save(
            db,
            run_id=run.id,
            workflow_id=workflow.id,
            phase_name="context-bootstrap",
            phase_attempt=2,
            payload={"phase_name": "context-bootstrap", "phase_attempt": 2, "output": {"prompt_path": "/tmp/prompt2.txt"}},
        )

        lease = WorkerLease(
            run_id=run.id,
            workflow_id=workflow.id,
            phase_name="learning-recall",
            phase_run_id=phase_2.id,
            worker_id="worker-local-1",
            status=WorkerLeaseState.ACTIVE.value,
        )
        metric = RunMetric(
            run_id=run.id,
            workflow_id=workflow.id,
            phase_name="context-bootstrap",
            metric_name="phase_duration_seconds",
            metric_value=1.25,
            metric_unit="seconds",
            tags=["phase", "duration"],
        )
        db.add(lease)
        db.add(metric)
        db.commit()

        latest = checkpoints.get_latest(db, run_id=run.id, phase_name="context-bootstrap")
        assert latest is not None
        assert latest.id == cp2.id
        assert latest.phase_attempt == 2

        old_cp = db.get(RunCheckpoint, cp1.id)
        assert old_cp is not None
        assert old_cp.is_latest is False

        phase_runs = (
            db.query(WorkflowPhaseRun)
            .filter(WorkflowPhaseRun.workflow_id == workflow.id, WorkflowPhaseRun.phase_name == "context-bootstrap")
            .order_by(WorkflowPhaseRun.attempt.asc())
            .all()
        )
        assert [row.attempt for row in phase_runs] == [1, 2]
        assert db.query(WorkerLease).filter(WorkerLease.run_id == run.id).count() == 1
        assert db.query(RunMetric).filter(RunMetric.run_id == run.id, RunMetric.metric_name == "phase_duration_seconds").count() == 1
