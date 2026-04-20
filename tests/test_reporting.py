from __future__ import annotations

import os
import tempfile
from pathlib import Path

from sqlalchemy.orm import Session

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_report_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"
os.environ["SECOPS_RUNTIME_ROOT"] = str(Path(tempfile.gettempdir()) / f"secops_reporting_runtime_{os.getpid()}")

from secops.db import Base, SessionLocal, engine
from secops.models import Artifact, Engagement, Fact, RunEvent, WorkflowExecution, WorkflowPhaseRun, WorkspaceRun
from secops.services.reporting import ReportingService


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed_run(db: Session) -> WorkspaceRun:
    engagement = Engagement(name="Report Test", mode="pentest", target="10.10.10.10", tags=["pentest"])
    db.add(engagement)
    db.flush()
    run = WorkspaceRun(
        engagement_id=engagement.id,
        mode=engagement.mode,
        workspace_id="pentest-report-test",
        status="running",
        objective="report",
        target="10.10.10.10",
        config_json={"ports": [], "services": [], "tags": ["pentest", "vantix"]},
    )
    db.add(run)
    db.flush()
    return run


def test_reporting_service_writes_markdown_and_json_with_provenance() -> None:
    reset_db()
    with SessionLocal() as db:
        run = _seed_run(db)
        workflow = WorkflowExecution(run_id=run.id, status="running", current_phase="report")
        db.add(workflow)
        db.flush()
        db.add(WorkflowPhaseRun(run_id=run.id, workflow_id=workflow.id, phase_name="recon-sidecar", attempt=1, status="completed", worker_id="worker-local-1"))
        db.add(Fact(run_id=run.id, source="recon", kind="service", value="http", confidence=0.9, tags=["recon"]))
        db.add(RunEvent(run_id=run.id, sequence=1, event_type="approval", level="warning", message="Approval required", payload_json={}))
        db.add(Artifact(run_id=run.id, kind="recon-log", path="/tmp/recon.log", metadata_json={}))
        db.commit()

        generated = ReportingService().generate(db, run)
        assert generated["markdown_path"].endswith("run_report.md")
        assert generated["json_path"].endswith("run_report.json")
        assert Path(generated["markdown_path"]).exists()
        assert Path(generated["json_path"]).exists()
        assert generated["summary"]["workflow_id"] == workflow.id
