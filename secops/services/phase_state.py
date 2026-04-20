from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from secops.models import Fact, Finding, WorkflowExecution, WorkspaceRun

PHASE_ORDER = [
    "flow-initialization",
    "recon",
    "knowledge-load",
    "vector-store",
    "research",
    "planning",
    "development",
    "execution",
    "reporting",
    "completed",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunPhaseService:
    def snapshot(self, run: WorkspaceRun) -> dict[str, Any]:
        config = dict(run.config_json or {})
        state = dict(config.get("phase_state") or {})
        if not state:
            state = self._default_state(reason="uninitialized")
            self._write(run, state)
        return state

    def initialize(self, run: WorkspaceRun, *, reason: str = "bootstrap") -> dict[str, Any]:
        state = self._state(
            current="recon",
            completed=["flow-initialization"],
            reason=reason,
        )
        self._write(run, state)
        return state

    def transition(self, run: WorkspaceRun, phase: str, *, reason: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        state = self.snapshot(run)
        current = phase if phase in PHASE_ORDER else state.get("current", "recon")
        completed = [name for name in PHASE_ORDER if name != "completed" and PHASE_ORDER.index(name) < PHASE_ORDER.index(current)]
        if current == "completed":
            completed = [name for name in PHASE_ORDER if name != "completed"]
        next_actions = [name for name in PHASE_ORDER if name not in completed and name != current]
        history = list(state.get("history") or [])
        history.append({"at": _now(), "phase": current, "reason": reason, "details": details or {}})
        new_state = {
            "current": current,
            "completed": completed,
            "pending": next_actions,
            "updated_at": _now(),
            "reason": reason,
            "history": history[-20:],
        }
        self._write(run, new_state)
        return new_state

    def refresh(self, db: Session, run: WorkspaceRun, *, reason: str = "refresh") -> dict[str, Any]:
        derived = self.derive(db, run)
        return self.transition(run, derived, reason=reason)

    def derive(self, db: Session, run: WorkspaceRun) -> str:
        if run.status in {"completed", "cancelled", "failed"}:
            return "completed"
        workflow = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.run_id == run.id)
            .order_by(WorkflowExecution.created_at.desc())
            .first()
        )
        if workflow is not None and workflow.current_phase:
            current = str(workflow.current_phase).strip().lower()
            if current in PHASE_ORDER:
                return current
            if current in {"context-bootstrap", "source-intake", "source-analysis"}:
                return "flow-initialization"
            if current == "learning-recall":
                return "knowledge-load"
            if current == "recon-sidecar":
                return "recon"
            if current == "browser-assessment":
                return "recon"
            if current == "cve-analysis":
                return "research"
            if current == "orchestrate":
                return "planning"
            if current == "learn-ingest":
                return "execution"
            if current == "report":
                return "reporting"

        findings = db.query(Finding).filter(Finding.run_id == run.id).all()
        if any(item.status in {"validated", "confirmed", "draft"} for item in findings):
            return "reporting"

        facts = db.query(Fact).filter(Fact.run_id == run.id).all()
        vector_statuses = {str((fact.metadata_json or {}).get("status", "")) for fact in facts if fact.kind == "vector"}
        if "executing" in vector_statuses:
            return "execution"
        if vector_statuses & {"planned", "selected", "validated"}:
            return "development"
        if any(fact.kind == "attack_chain" for fact in facts):
            return "planning"
        if any(fact.kind == "cve" for fact in facts):
            return "research"
        if any(fact.kind in {"service", "port", "host", "banner", "version"} for fact in facts):
            return "knowledge-load"
        state = self.snapshot(run)
        return str(state.get("current") or "recon")

    def _default_state(self, *, reason: str) -> dict[str, Any]:
        return self._state(current="flow-initialization", completed=[], reason=reason)

    def _state(self, *, current: str, completed: list[str], reason: str) -> dict[str, Any]:
        pending = [name for name in PHASE_ORDER if name not in completed and name != current]
        return {
            "current": current,
            "completed": completed,
            "pending": pending,
            "updated_at": _now(),
            "reason": reason,
            "history": [{"at": _now(), "phase": current, "reason": reason, "details": {}}],
        }

    def _write(self, run: WorkspaceRun, state: dict[str, Any]) -> None:
        config = dict(run.config_json or {})
        config["phase_state"] = state
        run.config_json = config
