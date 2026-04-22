"""P3-6 — structured diff between two runs."""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_runs_compare_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest
from fastapi import HTTPException

from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, Fact, Finding, WorkflowExecution, WorkflowPhaseRun, WorkspaceRun
from secops.routers.runs import compare_runs


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed_run(db, *, tag: str) -> WorkspaceRun:
    eng = Engagement(name=f"Cmp-{tag}", mode="pentest", target="10.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(
        engagement_id=eng.id,
        mode="pentest",
        workspace_id=f"ws-{tag}",
        status="completed",
        objective="cmp",
        target="10.0.0.1",
        config_json={},
    )
    db.add(run)
    db.flush()
    return run


def test_compare_runs_reports_findings_phases_and_vectors():
    _reset_db()
    with SessionLocal() as db:
        run_a = _seed_run(db, tag="a")
        run_b = _seed_run(db, tag="b")
        # Finding present in both under same fingerprint but severity bumped in B.
        db.add(Finding(run_id=run_a.id, title="XSS", severity="medium", status="validated",
                       fingerprint="fp-xss", disposition="draft"))
        db.add(Finding(run_id=run_b.id, title="XSS", severity="high", status="validated",
                       fingerprint="fp-xss", disposition="confirmed"))
        # Finding only in A and only in B.
        db.add(Finding(run_id=run_a.id, title="Old", severity="low", status="validated",
                       fingerprint="fp-only-a", disposition="draft"))
        db.add(Finding(run_id=run_b.id, title="New", severity="critical", status="validated",
                       fingerprint="fp-only-b", disposition="draft"))
        # Vectors in B only.
        db.add(Fact(run_id=run_b.id, source="orchestrator", kind="vector", value="V1",
                    confidence=0.7, tags=["vector"], fingerprint="v-1"))
        db.add(Fact(run_id=run_b.id, source="orchestrator", kind="vector", value="V2",
                    confidence=0.7, tags=["vector"], fingerprint="v-2"))
        # Phase durations: one faster in B, one slower.
        now = datetime.now(timezone.utc)
        wf_a = WorkflowExecution(run_id=run_a.id)
        wf_b = WorkflowExecution(run_id=run_b.id)
        db.add_all([wf_a, wf_b])
        db.flush()
        db.add(WorkflowPhaseRun(
            run_id=run_a.id, workflow_id=wf_a.id, phase_name="recon", status="completed",
            started_at=now - timedelta(seconds=120), completed_at=now - timedelta(seconds=60),
        ))
        db.add(WorkflowPhaseRun(
            run_id=run_b.id, workflow_id=wf_b.id, phase_name="recon", status="completed",
            started_at=now - timedelta(seconds=90), completed_at=now - timedelta(seconds=60),
        ))
        db.add(WorkflowPhaseRun(
            run_id=run_b.id, workflow_id=wf_b.id, phase_name="report", status="completed",
            started_at=now - timedelta(seconds=30), completed_at=now,
        ))
        db.commit()

        diff = compare_runs(a=run_a.id, b=run_b.id, db=db)

    only_a_fps = [row["fingerprint"] for row in diff["findings"]["only_in_a"]]
    only_b_fps = [row["fingerprint"] for row in diff["findings"]["only_in_b"]]
    assert only_a_fps == ["fp-only-a"]
    assert only_b_fps == ["fp-only-b"]
    changed_fps = [row["fingerprint"] for row in diff["findings"]["changed"]]
    assert changed_fps == ["fp-xss"]
    xss_changes = diff["findings"]["changed"][0]["changes"]
    assert xss_changes["severity"] == {"a": "medium", "b": "high"}
    assert xss_changes["disposition"] == {"a": "draft", "b": "confirmed"}

    recon = next(p for p in diff["phases"] if p["phase_name"] == "recon")
    assert recon["duration_a_seconds"] == pytest.approx(60.0, abs=0.5)
    assert recon["duration_b_seconds"] == pytest.approx(30.0, abs=0.5)
    assert recon["delta_seconds"] < 0  # B was faster

    report = next(p for p in diff["phases"] if p["phase_name"] == "report")
    assert report["duration_a_seconds"] is None
    assert report["duration_b_seconds"] is not None

    assert diff["vectors"] == {"count_a": 0, "count_b": 2}
    assert diff["findings"]["severity_b"].get("critical") == 1


def test_compare_runs_missing_run_returns_404():
    _reset_db()
    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            compare_runs(a="nope", b="nope", db=db)
        assert exc.value.status_code == 404
