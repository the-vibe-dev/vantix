from __future__ import annotations

import os
import tempfile
from pathlib import Path

from sqlalchemy.orm import Session

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_phase_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"
os.environ["SECOPS_RUNTIME_ROOT"] = str(Path(tempfile.gettempdir()) / f"secops_phase_runtime_{os.getpid()}")

from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, WorkflowExecution, WorkflowPhaseRun, WorkspaceRun
from secops.services.execution import ExecutionManager
from secops.services.policies import ExecutionPolicyService
from secops.services.workflows.engine import WorkflowEngine
from secops.services.workflows.retries import classify_retry
from secops.services.workflows.types import PhaseStatus


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed_run(db: Session) -> WorkspaceRun:
    engagement = Engagement(name="Phase Test", mode="pentest", target="10.10.10.10", tags=["pentest"])
    db.add(engagement)
    db.flush()
    run = WorkspaceRun(
        engagement_id=engagement.id,
        mode=engagement.mode,
        workspace_id="pentest-phase-test",
        status="planned",
        objective="phase test",
        target="10.10.10.10",
        config_json={"ports": [], "services": [], "tags": ["pentest", "vantix"]},
    )
    db.add(run)
    db.flush()
    return run


def test_transient_retry_creates_new_attempt() -> None:
    reset_db()
    service = WorkflowEngine()
    with SessionLocal() as db:
        run = _seed_run(db)
        workflow = service.enqueue_run(db, run)
        db.commit()

        claim = service.claim_next_phase(db, worker_id="worker-a", lease_seconds=5)
        assert claim is not None
        decision = classify_retry("timeout")
        assert decision.retryable is True
        assert decision.delay_seconds > 0
        retry = service.schedule_retry(
            db,
            claim,
            retry_class=decision.retry_class.value,
            delay_seconds=decision.delay_seconds,
            reason=decision.reason,
        )
        db.commit()

        assert retry is not None
        assert retry.attempt == 2
        assert retry.status == PhaseStatus.RETRYING.value
        current = (
            db.query(WorkflowPhaseRun)
            .filter(WorkflowPhaseRun.workflow_id == workflow.id, WorkflowPhaseRun.phase_name == claim.phase_name)
            .order_by(WorkflowPhaseRun.attempt.asc())
            .all()
        )
        assert len(current) == 2
        assert current[0].status == PhaseStatus.FAILED.value


def test_blocked_state_is_normalized() -> None:
    reset_db()
    service = WorkflowEngine()
    with SessionLocal() as db:
        run = _seed_run(db)
        service.enqueue_run(db, run)
        claim = service.claim_next_phase(db, worker_id="worker-a", lease_seconds=5)
        assert claim is not None
        service.mark_phase_blocked(db, claim, reason="approval required")
        db.commit()
        wf = db.get(WorkflowExecution, claim.workflow_id)
        assert wf is not None
        assert wf.status == "blocked"
        assert run.status == "blocked"


def test_policy_redaction_and_verdicts() -> None:
    policy = ExecutionPolicyService()
    text = "token=abc123 sk-ABCDEF1234567890"
    redacted = policy._redact(text, redactions=["abc123"])
    assert "[REDACTED]" in redacted


def test_scope_policy_approval_grant_is_consumed_once() -> None:
    reset_db()
    manager = ExecutionManager()
    with SessionLocal() as db:
        engagement = Engagement(
            name="Scope Grant",
            mode="pentest",
            target="192.168.1.95",
            tags=["pentest"],
            metadata_json={"scope": {"allowed": ["192.168.1.95"], "excludes": [], "allow_private": False}},
        )
        db.add(engagement)
        db.flush()
        run = WorkspaceRun(
            engagement_id=engagement.id,
            mode="pentest",
            workspace_id="pentest-scope-grant",
            status="queued",
            objective="scope grant test",
            target="192.168.1.95",
            config_json={"approval_grants": {"scope": 1}},
        )
        db.add(run)
        db.flush()

        first = manager._enforce_scope(db, run, "192.168.1.95")
        second = manager._enforce_scope(db, run, "192.168.1.95")

        assert first.allowed is True
        assert second.allowed is False
        assert "denied range" in second.reason
        assert int((run.config_json.get("approval_grants") or {}).get("scope", -1)) == 0


def test_validation_config_normalizes_high_risk_surfaces_defaults() -> None:
    reset_db()
    manager = ExecutionManager()
    with SessionLocal() as db:
        run = _seed_run(db)
        cfg = manager._validation_config(run)
        assert cfg["high_risk_surfaces"]["enabled"] is True
        assert cfg["high_risk_surfaces"]["label"] == "High Risk Surfaces"

        run.config_json = {
            **(run.config_json or {}),
            "validation": {
                "high_risk_surfaces": {
                    "enabled": False,
                    "label": "Controlled Validation",
                }
            },
        }
        cfg = manager._validation_config(run)
        assert cfg["high_risk_surfaces"]["enabled"] is False
        assert cfg["high_risk_surfaces"]["label"] == "Controlled Validation"
