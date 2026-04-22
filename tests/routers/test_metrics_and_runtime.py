"""P3-2 + P3-8 — Prometheus metrics + runtime health snapshots."""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_metrics_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

from secops.db import Base, SessionLocal, engine
from secops.models import (
    Engagement,
    RunEvent,
    WorkerLease,
    WorkerRuntimeStatus,
    WorkspaceRun,
)
from secops.routers.health import runtime_health
from secops.routers.metrics import prometheus_metrics


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed_run(db) -> WorkspaceRun:
    eng = Engagement(name="Metrics", mode="pentest", target="10.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(
        engagement_id=eng.id,
        mode="pentest",
        workspace_id=f"ws-{eng.id[:8]}",
        status="running",
        objective="metrics",
        target="10.0.0.1",
        config_json={},
    )
    db.add(run)
    db.flush()
    return run


def test_prometheus_metrics_renders_policy_counters_and_lease_gauges():
    _reset_db()
    with SessionLocal() as db:
        run = _seed_run(db)
        db.add_all([
            RunEvent(run_id=run.id, event_type="policy_decision", message="x",
                     payload_json={"action_kind": "network", "verdict": "allow"}),
            RunEvent(run_id=run.id, event_type="policy_decision", message="x",
                     payload_json={"action_kind": "network", "verdict": "allow"}),
            RunEvent(run_id=run.id, event_type="policy_decision", message="x",
                     payload_json={"action_kind": "exec", "verdict": "block"}),
            RunEvent(run_id=run.id, event_type="run_status", message="started",
                     payload_json={}),
        ])
        db.add_all([
            WorkerLease(run_id=run.id, phase_name="recon", worker_id="w1", status="active"),
            WorkerLease(run_id=run.id, phase_name="recon", worker_id="w2", status="active"),
            WorkerLease(run_id=run.id, phase_name="report", worker_id="w3", status="completed"),
        ])
        db.add(WorkerRuntimeStatus(
            worker_id="w1", hostname="h", pid=1, status="running",
            heartbeat_at=datetime.now(timezone.utc) - timedelta(seconds=10),
        ))
        db.commit()

        response = prometheus_metrics(db)
        body = response.body.decode("utf-8")

    assert "vantix_policy_decisions_total" in body
    assert 'action_kind="network",verdict="allow"} 2' in body
    assert 'action_kind="exec",verdict="block"} 1' in body
    # run_status events don't leak into the policy counter.
    assert "run_status" not in body
    # Lease state gauges render per status.
    assert 'vantix_worker_leases{state="active"} 2' in body
    assert 'vantix_worker_leases{state="completed"} 1' in body
    # Heartbeat age gauge is present and non-negative.
    assert "vantix_worker_heartbeat_age_seconds" in body


def test_runtime_health_reports_workers_and_stale_candidates():
    _reset_db()
    with SessionLocal() as db:
        run = _seed_run(db)
        now = datetime.now(timezone.utc)
        db.add_all([
            WorkerLease(run_id=run.id, phase_name="recon", worker_id="w1", status="active"),
            WorkerLease(run_id=run.id, phase_name="recon", worker_id="w2", status="active"),
        ])
        db.add_all([
            WorkerRuntimeStatus(
                worker_id="w1", hostname="h", pid=1, status="running",
                heartbeat_at=now - timedelta(seconds=5),
            ),
            WorkerRuntimeStatus(
                worker_id="w2", hostname="h", pid=2, status="running",
                heartbeat_at=now - timedelta(seconds=600),  # stale
            ),
        ])
        db.commit()

        result = runtime_health(db)

    assert result["leases"]["total"] == 2
    assert result["leases"]["by_state"]["active"] == 2
    assert result["workers"]["total"] == 2
    stale_ids = [row["worker_id"] for row in result["workers"]["stale"]]
    assert stale_ids == ["w2"]
    # Latest age is the freshest worker's age (w1 — 5 s), within tolerance.
    assert result["workers"]["latest_heartbeat_age_seconds"] is not None
    assert result["workers"]["latest_heartbeat_age_seconds"] < 30
    assert result["thresholds"]["stale_heartbeat_seconds"] == 120
