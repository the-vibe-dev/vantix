from __future__ import annotations

import json
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
from secops.routers.runs import get_run_replay
from secops.services.execution import ExecutionManager
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
        auth_path = Path(tempfile.gettempdir()) / "vantix-report-browser-auth.json"
        auth_path.write_text(
            json.dumps({"auth_transitions": [{"stage": "post-auth", "status": "success"}], "dom_diffs": [{"stage": "auth-transition", "cookie_delta": 1}]}),
            encoding="utf-8",
        )
        session_path = Path(tempfile.gettempdir()) / "vantix-report-browser-session.json"
        session_path.write_text(
            json.dumps({"entry_url": "http://127.0.0.1:8080", "current_url": "http://127.0.0.1:8080/home", "authenticated": "success", "pages_visited": 3, "blocked_actions": []}),
            encoding="utf-8",
        )
        js_path = Path(tempfile.gettempdir()) / "vantix-report-browser-js.json"
        js_path.write_text(
            json.dumps({"pages": [{"url": "http://127.0.0.1:8080/home", "js_signals": [{"kind": "app-config", "signal": "window.__APP_CONFIG__"}], "route_hints": ["/admin"]}]}),
            encoding="utf-8",
        )
        db.add(Artifact(run_id=run.id, kind="browser-auth-state", path=str(auth_path), metadata_json={}))
        db.add(Artifact(run_id=run.id, kind="browser-session-summary", path=str(session_path), metadata_json={}))
        db.add(Artifact(run_id=run.id, kind="browser-js-signals", path=str(js_path), metadata_json={}))
        db.commit()

        generated = ReportingService().generate(db, run)
        assert generated["markdown_path"].endswith("run_report.md")
        assert generated["json_path"].endswith("run_report.json")
        assert generated["comprehensive_markdown_path"].endswith("comprehensive_security_assessment_report.md")
        assert generated["comprehensive_json_path"].endswith("comprehensive_security_assessment_report.json")
        assert generated["artifact_index_path"].endswith("artifact_index.json")
        assert generated["timeline_csv_path"].endswith("timeline.csv")
        assert Path(generated["markdown_path"]).exists()
        assert Path(generated["json_path"]).exists()
        assert Path(generated["comprehensive_markdown_path"]).exists()
        assert Path(generated["comprehensive_json_path"]).exists()
        assert Path(generated["artifact_index_path"]).exists()
        assert Path(generated["timeline_csv_path"]).exists()
        assert generated["summary"]["workflow_id"] == workflow.id
        assert generated["summary"]["browser_assessment"]["authenticated"] == "success"
        assert generated["summary"]["browser_assessment"]["auth_transitions"][0]["status"] == "success"
        comprehensive = json.loads(Path(generated["comprehensive_json_path"]).read_text(encoding="utf-8"))
        assert "vulnerability_type_summary" in comprehensive
        assert "timeline" in comprehensive
        timeline_head = Path(generated["timeline_csv_path"]).read_text(encoding="utf-8").splitlines()[0]
        assert timeline_head == "sequence,event_type,level,message,created_at"


def test_run_replay_returns_phase_history_and_events() -> None:
    reset_db()
    with SessionLocal() as db:
        run = _seed_run(db)
        run.config_json = {
            **(run.config_json or {}),
            "phase_state": {
                "current": "reporting",
                "completed": ["flow-initialization", "recon", "knowledge-load"],
                "pending": ["completed"],
                "updated_at": "2026-01-01T00:00:00Z",
                "reason": "report-ready",
                "history": [
                    {"at": "2026-01-01T00:00:00Z", "phase": "recon", "reason": "chat", "details": {}},
                    {"at": "2026-01-01T00:05:00Z", "phase": "reporting", "reason": "finding-promoted", "details": {}},
                ],
            },
        }
        db.add(RunEvent(run_id=run.id, sequence=1, event_type="phase", level="info", message="Recon completed", payload_json={"phase": "recon"}))
        db.add(RunEvent(run_id=run.id, sequence=2, event_type="approval", level="warning", message="Approval granted: continue", payload_json={"reason": "exploit_validation"}))
        db.add(Artifact(run_id=run.id, kind="report", path="/tmp/report.md", metadata_json={}))
        db.add(Artifact(run_id=run.id, kind="report-json", path="/tmp/report.json", metadata_json={}))
        db.commit()

        payload = get_run_replay(run.id, db=db)
        assert payload["run_id"] == run.id
        assert len(payload["phase_history"]) == 2
        assert payload["report_path"] == "/tmp/report.md"
        assert payload["events"][0]["event_type"] == "phase_transition"
        assert payload["events"][1]["event_type"] == "approval_resolved"


def test_report_phase_promotes_high_signal_vectors_when_findings_empty() -> None:
    reset_db()
    with SessionLocal() as db:
        run = _seed_run(db)
        db.add(
            Fact(
                run_id=run.id,
                source="recon-web",
                kind="vector",
                value="source-disclosure on 80",
                confidence=0.85,
                tags=["web", "candidate"],
                metadata_json={
                    "title": "source-disclosure on 80",
                    "summary": "Potential source disclosure identified.",
                    "status": "planned",
                    "severity": "high",
                    "evidence": "http://target/server.py",
                    "next_action": "validate safely and capture proof",
                    "score": 0.85,
                },
            )
        )
        db.commit()
        manager = ExecutionManager()
        manager._ensure_findings_for_report(db, run.id)
        db.commit()
        generated = ReportingService().generate(db, run)
        assert generated["summary"]["findings"]
        assert generated["summary"]["findings"][0]["title"] == "source-disclosure on 80"
