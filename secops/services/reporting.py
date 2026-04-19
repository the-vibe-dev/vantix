from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from secops.models import Artifact, Fact, RunEvent, WorkspaceRun, WorkflowExecution, WorkflowPhaseRun
from secops.services.storage import StorageLayout


class ReportingService:
    def __init__(self) -> None:
        self.storage = StorageLayout()

    def generate(self, db: Session, run: WorkspaceRun) -> dict:
        paths = self.storage.for_workspace(run.workspace_id)
        facts = db.query(Fact).filter(Fact.run_id == run.id).order_by(Fact.created_at.asc()).all()
        events = db.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.sequence.asc()).all()
        artifacts = db.query(Artifact).filter(Artifact.run_id == run.id).order_by(Artifact.created_at.asc()).all()
        workflow = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.run_id == run.id)
            .order_by(WorkflowExecution.created_at.desc())
            .first()
        )
        phase_attempts = (
            db.query(WorkflowPhaseRun)
            .filter(WorkflowPhaseRun.run_id == run.id)
            .order_by(WorkflowPhaseRun.created_at.asc())
            .all()
        )

        report_json = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run.id,
            "workspace_id": run.workspace_id,
            "mode": run.mode,
            "target": run.target,
            "objective": run.objective,
            "workflow_id": workflow.id if workflow else "",
            "workflow_status": workflow.status if workflow else run.status,
            "phase_attempts": [
                {
                    "phase": row.phase_name,
                    "attempt": row.attempt,
                    "status": row.status,
                    "retry_class": row.retry_class,
                    "worker_id": row.worker_id,
                }
                for row in phase_attempts
            ],
            "facts": [{"id": fact.id, "kind": fact.kind, "value": fact.value, "source": fact.source, "confidence": fact.confidence} for fact in facts],
            "artifacts": [{"id": art.id, "kind": art.kind, "path": art.path} for art in artifacts],
            "events": [{"id": ev.id, "sequence": ev.sequence, "type": ev.event_type, "level": ev.level, "message": ev.message} for ev in events[-80:]],
            "negative_evidence": [fact.value for fact in facts if fact.kind in {"negative_evidence", "no_finding"}],
        }

        md_lines = [
            f"# Run Report: {run.workspace_id}",
            "",
            "## Run Overview",
            f"- Run ID: {run.id}",
            f"- Mode: {run.mode}",
            f"- Target: {run.target}",
            f"- Objective: {run.objective}",
            f"- Workflow: {report_json['workflow_id'] or '(none)'}",
            f"- Workflow status: {report_json['workflow_status']}",
            "",
            "## Phase Timeline",
        ]
        for phase in report_json["phase_attempts"]:
            md_lines.append(
                f"- {phase['phase']} attempt={phase['attempt']} status={phase['status']} retry={phase['retry_class']} worker={phase['worker_id'] or 'n/a'}"
            )
        md_lines.extend(["", "## Findings And Evidence"])
        for fact in report_json["facts"][:80]:
            md_lines.append(f"- [{fact['kind']}] {fact['value']} (source={fact['source']}, confidence={fact['confidence']})")
        md_lines.extend(["", "## Artifacts With Provenance"])
        for art in report_json["artifacts"][:80]:
            md_lines.append(f"- {art['kind']}: {art['path']} (artifact_id={art['id']})")
        if report_json["negative_evidence"]:
            md_lines.extend(["", "## Negative Evidence"])
            for item in report_json["negative_evidence"][:40]:
                md_lines.append(f"- {item}")
        md_lines.extend(["", "## Approvals And Blocked Actions"])
        for event in report_json["events"]:
            if event["type"] in {"approval", "run_status"} or "blocked" in event["message"].lower():
                md_lines.append(f"- [{event['type']}] {event['message']}")
        md_lines.extend(["", "## Next Steps", "- Review blocked/failed attempts.", "- Promote validated findings.", "- Replan from planning bundle if evidence is insufficient."])

        md_path = paths.artifacts / "run_report.md"
        json_path = paths.artifacts / "run_report.json"
        paths.write_text(Path(md_path), "\n".join(md_lines) + "\n")
        paths.write_json(Path(json_path), report_json)
        return {"markdown_path": str(md_path), "json_path": str(json_path), "summary": report_json}
