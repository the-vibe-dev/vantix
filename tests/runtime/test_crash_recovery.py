"""P1-1 — re-claimed phases merge via fingerprint UPSERT, don't duplicate.

Simulates the two retry paths:

1. Stale-lease scavenger re-claim: worker claims a phase, writes facts via
   ``upsert_fact_by_fingerprint`` (crash mid-phase — facts committed before
   death), lease expires, scavenger marks the row RETRYING, a new worker
   re-claims the same row, handler re-runs and upserts the same fingerprints
   → fact count does not grow.

2. Handler-requested retry: handler fails with TRANSIENT, ``schedule_retry``
   creates a new phase-run row with the same idempotency key; re-run
   upserts same fingerprints → fact count does not grow.
"""
from __future__ import annotations

import os
import tempfile
from datetime import timedelta
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_runtime_crash_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, Fact, WorkflowExecution, WorkflowPhaseRun, WorkspaceRun
from secops.services.workflows.engine import WorkflowEngine, utcnow
from secops.services.workflows.idempotency import (
    phase_idempotency_key,
    upsert_fact_by_fingerprint,
)
from secops.services.workflows.types import PhaseStatus, WorkflowStatus


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed_run(db) -> WorkspaceRun:
    eng = Engagement(name="Crash Recovery", mode="pentest", target="10.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(
        engagement_id=eng.id,
        mode="pentest",
        workspace_id=f"ws-{eng.id[:8]}",
        status="running",
        objective="crash recovery",
        target="10.0.0.1",
        config_json={},
    )
    db.add(run)
    db.flush()
    return run


def _run_handler_facts(db, run: WorkspaceRun) -> None:
    """Simulated handler: writes two facts with stable fingerprints."""
    for fp, value in [("fp-alpha", "alpha"), ("fp-beta", "beta")]:
        upsert_fact_by_fingerprint(
            db,
            run_id=run.id,
            fingerprint=fp,
            kind="vector",
            source="handler",
            value=value,
            confidence=0.5,
            metadata={"attempt_value": value},
        )


def test_phase_idempotency_key_is_stable() -> None:
    a = phase_idempotency_key("run-1", "orchestrate", {"target": "t"})
    b = phase_idempotency_key("run-1", "orchestrate", {"target": "t"})
    c = phase_idempotency_key("run-1", "orchestrate", {"target": "u"})
    assert a == b
    assert a != c
    assert len(a) == 32


def test_upsert_merges_on_repeat() -> None:
    _reset_db()
    with SessionLocal() as db:
        run = _seed_run(db)
        first, created = upsert_fact_by_fingerprint(
            db, run_id=run.id, fingerprint="fp-x", kind="vector",
            source="handler", value="v1", confidence=0.3,
            tags=["a"], metadata={"k1": 1}, validated=False,
        )
        assert created is True
        second, created2 = upsert_fact_by_fingerprint(
            db, run_id=run.id, fingerprint="fp-x", kind="vector",
            source="handler", value="v1", confidence=0.7,
            tags=["b"], metadata={"k2": 2}, validated=True,
        )
        assert created2 is False
        assert first.id == second.id
        # confidence monotonic, validated latches, metadata merged, tags unioned
        assert second.confidence == 0.7
        assert second.validated is True
        assert second.metadata_json == {"k1": 1, "k2": 2}
        assert set(second.tags) == {"a", "b"}
        assert db.query(Fact).filter(Fact.run_id == run.id).count() == 1


def test_scavenger_reclaim_does_not_duplicate_facts() -> None:
    _reset_db()
    with SessionLocal() as db:
        run = _seed_run(db)
        workflow = WorkflowExecution(
            run_id=run.id,
            workflow_kind="vantix-run",
            status=WorkflowStatus.QUEUED.value,
            current_phase="orchestrate",
        )
        db.add(workflow)
        db.flush()
        phase_run = WorkflowPhaseRun(
            run_id=run.id,
            workflow_id=workflow.id,
            phase_name="orchestrate",
            attempt=1,
            status=PhaseStatus.PENDING.value,
            metadata_json={},
        )
        db.add(phase_run)
        db.flush()
        db.commit()

        engine_svc = WorkflowEngine()

        # First worker claims, runs handler, commits facts, then "dies".
        claim1 = engine_svc.claim_next_phase(db, worker_id="worker-A", lease_seconds=1)
        assert claim1 is not None
        phase_run_row = db.get(WorkflowPhaseRun, claim1.phase_run_id)
        key = (phase_run_row.metadata_json or {}).get("idempotency_key")
        assert key, "claim_next_phase must stamp an idempotency_key"
        _run_handler_facts(db, run)
        db.commit()
        facts_after_first = db.query(Fact).filter(Fact.run_id == run.id).count()
        assert facts_after_first == 2

        # Simulate lease expiry: push lease_expires_at into the past.
        phase_run_row.lease_expires_at = utcnow() - timedelta(seconds=5)
        db.commit()

        # Scavenger recovers the stale claim. Fresh session to mirror a
        # separate worker and avoid SQLite tz-naive/aware evaluator issues.
        db.close()

    with SessionLocal() as db:
        engine_svc = WorkflowEngine()
        recovered = engine_svc.scavenge_stale_runtime(db)
        db.commit()
        assert recovered["recovered_claims"] == 1
        refreshed = db.get(WorkflowPhaseRun, claim1.phase_run_id)
        assert refreshed.status == PhaseStatus.RETRYING.value

    with SessionLocal() as db:
        engine_svc = WorkflowEngine()
        run = db.query(WorkspaceRun).first()
        # Second worker claims the same row and re-runs the handler.
        claim2 = engine_svc.claim_next_phase(db, worker_id="worker-B", lease_seconds=60)
        assert claim2 is not None
        assert claim2.phase_run_id == claim1.phase_run_id
        key2 = (db.get(WorkflowPhaseRun, claim2.phase_run_id).metadata_json or {}).get("idempotency_key")
        assert key2 == key, "idempotency key must survive scavenger re-claim"
        _run_handler_facts(db, run)
        db.commit()
        facts_after_second = db.query(Fact).filter(Fact.run_id == run.id).count()
        assert facts_after_second == facts_after_first, (
            f"re-claim duplicated facts: {facts_after_first} → {facts_after_second}"
        )


def test_schedule_retry_preserves_idempotency_key() -> None:
    _reset_db()
    with SessionLocal() as db:
        run = _seed_run(db)
        workflow = WorkflowExecution(
            run_id=run.id,
            workflow_kind="vantix-run",
            status=WorkflowStatus.QUEUED.value,
            current_phase="orchestrate",
        )
        db.add(workflow)
        db.flush()
        phase_run = WorkflowPhaseRun(
            run_id=run.id,
            workflow_id=workflow.id,
            phase_name="orchestrate",
            attempt=1,
            status=PhaseStatus.PENDING.value,
            metadata_json={"inputs": {"target": "10.0.0.1"}},
        )
        db.add(phase_run)
        db.flush()
        db.commit()

        engine_svc = WorkflowEngine()
        claim = engine_svc.claim_next_phase(db, worker_id="worker-A", lease_seconds=60)
        assert claim is not None
        _run_handler_facts(db, run)
        db.commit()

        original_row = db.get(WorkflowPhaseRun, claim.phase_run_id)
        key = (original_row.metadata_json or {}).get("idempotency_key")
        assert key

        next_row = engine_svc.schedule_retry(
            db, claim, retry_class="transient", delay_seconds=0, reason="simulate transient"
        )
        db.commit()
        assert next_row is not None
        next_row_id = next_row.id
        assert next_row.attempt == 2
        assert (next_row.metadata_json or {}).get("idempotency_key") == key
        db.close()

    # Wait out the min 1-second retry delay set by schedule_retry.
    import time
    time.sleep(1.2)

    with SessionLocal() as db:
        engine_svc = WorkflowEngine()
        run = db.query(WorkspaceRun).first()
        # Re-claim the retry row, re-run handler, assert no dup facts.
        claim2 = engine_svc.claim_next_phase(db, worker_id="worker-B", lease_seconds=60)
        assert claim2 is not None
        assert claim2.phase_run_id == next_row_id
        key2 = (db.get(WorkflowPhaseRun, claim2.phase_run_id).metadata_json or {}).get("idempotency_key")
        assert key2 == key
        _run_handler_facts(db, run)
        db.commit()
        assert db.query(Fact).filter(Fact.run_id == run.id).count() == 2
