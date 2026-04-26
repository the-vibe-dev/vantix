from __future__ import annotations

from datetime import datetime, timezone

from secops.execution.constants import ROLE_DISPLAY_NAMES, TASK_METADATA
from secops.models import AgentSession, Task, WorkspaceRun


class SessionMixin:
    """Task lifecycle + agent-session provisioning.

    Extracted from ExecutionManager. Methods rely on ``self.nas`` and
    ``self.events`` from peer mixins / __init__.
    """

    def _task_by_kind(self, db, run_id: str, kind: str) -> Task:
        task = (
            db.query(Task)
            .filter(Task.run_id == run_id, Task.kind == kind)
            .order_by(Task.created_at.desc())
            .first()
        )
        if task is not None:
            return task
        sequence = (db.query(Task).filter(Task.run_id == run_id).count() or 0) + 1
        task_name, task_description = TASK_METADATA.get(
            kind,
            (kind.replace("-", " ").title(), f"Auto-created task for {kind}"),
        )
        task = Task(
            run_id=run_id,
            name=task_name,
            description=task_description,
            kind=kind,
            status="pending",
            sequence=sequence,
        )
        db.add(task)
        db.flush()
        return task

    def _set_vantix_task_status(self, db, run_id: str, kind: str, status: str, result: dict | None = None) -> None:
        row = (
            db.query(Task)
            .filter(Task.run_id == run_id, Task.kind == kind)
            .order_by(Task.created_at.desc())
            .first()
        )
        if row is None:
            row = self._task_by_kind(db, run_id, kind)
        row.status = status
        if result:
            row.result_json = {**(row.result_json or {}), **result}

    def _create_agent_session(self, db, run_id: str, role: str, name: str, paths) -> AgentSession:
        existing = (
            db.query(AgentSession)
            .filter(AgentSession.run_id == run_id, AgentSession.role == role)
            .order_by(AgentSession.started_at.desc())
            .first()
        )
        if existing is not None:
            existing.name = name
            existing.workspace_path = str(paths.agents / role)
            existing.prompt_path = str(paths.prompts / f"{role}.txt")
            existing.log_path = str(paths.logs / f"{role}.log")
            existing.status = "pending"
            existing.completed_at = None
            db.flush()
            return existing
        session = AgentSession(
            run_id=run_id,
            role=role,
            name=name,
            status="pending",
            workspace_path=str(paths.agents / role),
            prompt_path=str(paths.prompts / f"{role}.txt"),
            log_path=str(paths.logs / f"{role}.log"),
            metadata_json={},
        )
        db.add(session)
        db.flush()
        run = db.get(WorkspaceRun, run_id)
        if run is not None:
            from secops.services.skills import SkillApplicationService

            SkillApplicationService().apply_to_run(db, run)
        return session

    def _set_role_status(self, db, run_id: str, role: str, status: str) -> None:
        agent = (
            db.query(AgentSession)
            .filter(AgentSession.run_id == run_id, AgentSession.role == role)
            .order_by(AgentSession.started_at.desc())
            .first()
        )
        if agent is None:
            run = db.get(WorkspaceRun, run_id)
            if run is None:
                return
            paths = self.nas.for_workspace(run.workspace_id)
            agent = AgentSession(
                run_id=run_id,
                role=role,
                name=ROLE_DISPLAY_NAMES.get(role, role.replace("_", " ").title()),
                status="pending",
                workspace_path=str(paths.agents / role),
                prompt_path=str(paths.prompts / f"{role}.txt"),
                log_path=str(paths.logs / f"{role}.log"),
                metadata_json={},
            )
            db.add(agent)
            db.flush()
            from secops.services.skills import SkillApplicationService

            SkillApplicationService().apply_to_run(db, run)
        previous = str(agent.status or "")
        agent.status = status
        if status in {"completed", "failed", "blocked"}:
            agent.completed_at = datetime.now(timezone.utc)
        if previous != status:
            self.events.emit(
                db,
                run_id,
                "agent_status",
                f"{role}:{status}",
                payload={"role": role, "status": status, "previous": previous},
            )
