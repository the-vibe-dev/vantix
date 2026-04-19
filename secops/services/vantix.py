from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from secops.config import settings
from secops.models import Action, AgentSession, Engagement, Fact, OperatorNote, RunMessage, Task, WorkspaceRun
from secops.services.events import RunEventService
from secops.services.learning import LearningService
from secops.services.memory_writer import DenseMemoryRecord, MemoryWriteService
from secops.services.run_service import RunService
from secops.services.skills import SkillApplicationService
from secops.services.storage import StorageLayout

TARGET_RE = re.compile(r"(?i)\b((?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|https?://[a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+|[a-z0-9][a-z0-9.-]+\.[a-z]{2,})(?=\s|$|[,.;])")

SPECIALIST_TASKS = [
    ("flow-initialization", "Orchestrator", "Normalize target, objective, scope, and run state."),
    ("vantix-recon", "Vantix Recon", "Collect low-noise service, port, and target facts."),
    ("knowledge-load", "Knowledge Base", "Load dense memory, learning hits, tool guidance, and prior cases."),
    ("vector-store", "Vector Store", "Rank similar cases and candidate attack patterns."),
    ("research", "Researcher", "Query CVE, exploit, and vulnerability intelligence."),
    ("planning", "Orchestrator Planning", "Select next action and branch between recon, development, execution, or report."),
    ("development", "Developer", "Prepare validation helpers, payload notes, or exploit implementation guidance."),
    ("execution", "Executor", "Run the selected vector through current execution controls."),
    ("reporting", "Vantix Report", "Summarize evidence, artifacts, validated findings, and next steps."),
]

ROLE_NAMES = {
    "orchestrator": "Orchestrator",
    "recon": "Vantix Recon",
    "knowledge_base": "Knowledge Base",
    "vector_store": "Vector Store",
    "researcher": "Researcher",
    "developer": "Developer",
    "executor": "Executor",
    "reporter": "Vantix Report",
}


class VantixScheduler:
    def __init__(self) -> None:
        self.events = RunEventService()
        self.memory = MemoryWriteService()
        self.skills = SkillApplicationService()
        self.storage = StorageLayout()

    def bootstrap(self, db: Session, run: WorkspaceRun, *, reason: str = "chat") -> str:
        self._seed_tasks(db, run)
        self._seed_agents(db, run)
        self._seed_initial_vector(db, run)
        db.flush()
        self.skills.apply_to_run(db, run)
        self._message(db, run.id, "orchestrator", "Vantix", self._orchestrator_summary(run, reason), {"reason": reason})
        self.events.emit(db, run.id, "scheduler", "Vantix scheduler initialized", payload={"reason": reason, "roles": list(ROLE_NAMES)})
        self._write_memory(db, run, reason)
        return "scheduler-initialized"

    def replan(self, db: Session, run: WorkspaceRun, *, reason: str = "chat-guidance") -> str:
        self._seed_tasks(db, run)
        self._seed_agents(db, run)
        self._seed_initial_vector(db, run)
        db.flush()
        self.skills.apply_to_run(db, run)
        self._message(db, run.id, "orchestrator", "Vantix", f"Replan queued from {reason}. Current target: {run.target or 'unknown'}. Objective remains: {run.objective}", {"reason": reason})
        self.events.emit(db, run.id, "scheduler", "Vantix replan requested", payload={"reason": reason})
        self._write_memory(db, run, reason)
        return "replan-queued"

    def _seed_tasks(self, db: Session, run: WorkspaceRun) -> None:
        existing = {task.kind: task for task in db.execute(select(Task).where(Task.run_id == run.id)).scalars().all()}
        max_sequence = max((task.sequence for task in existing.values()), default=0)
        next_sequence = max_sequence + 1
        for kind, name, description in SPECIALIST_TASKS:
            if kind in existing:
                continue
            task = Task(
                run_id=run.id,
                name=name,
                description=description,
                kind=kind,
                status="pending",
                sequence=next_sequence,
                context_json={"vantix_role": kind},
            )
            db.add(task)
            db.flush()
            db.add(Action(task_id=task.id, name=f"{name} work item", tool="vantix-scheduler", command="scheduler", status="planned"))
            next_sequence += 1

    def _seed_agents(self, db: Session, run: WorkspaceRun) -> None:
        paths = self.storage.for_workspace(run.workspace_id)
        existing = {agent.role for agent in db.execute(select(AgentSession).where(AgentSession.run_id == run.id)).scalars().all()}
        for role, name in ROLE_NAMES.items():
            if role in existing:
                continue
            db.add(
                AgentSession(
                    run_id=run.id,
                    role=role,
                    name=name,
                    status="pending",
                    workspace_path=str(paths.agents / role),
                    prompt_path=str(paths.prompts / f"{role}.txt"),
                    log_path=str(paths.logs / f"{role}.log"),
                    metadata_json={"scheduler": "vantix", "default_runtime": "codex"},
                )
            )

    def _seed_initial_vector(self, db: Session, run: WorkspaceRun) -> None:
        exists = db.execute(select(Fact).where(Fact.run_id == run.id, Fact.kind == "vector")).first()
        if exists:
            return
        title = "Initial evidence-driven validation path"
        summary = "Start with low-noise recon, memory/CVE correlation, then select an execution vector only when evidence supports it."
        db.add(
            Fact(
                run_id=run.id,
                source="scheduler",
                kind="vector",
                value=title,
                confidence=0.35,
                tags=["vantix", "candidate"],
                metadata_json={
                    "title": title,
                    "summary": summary,
                    "source": "scheduler",
                    "severity": "info",
                    "status": "candidate",
                    "evidence": f"Target: {run.target or 'unknown'}; objective: {run.objective}",
                    "next_action": "run Vantix Recon and correlate memory/CVE intel",
                    "noise_level": "quiet",
                    "requires_approval": False,
                    "skill_id": "recon_advisor",
                    "scope_check": "pending",
                    "safety_notes": "No exploit execution until scope and evidence are confirmed.",
                },
            )
        )

    def _orchestrator_summary(self, run: WorkspaceRun, reason: str) -> str:
        return (
            f"Vantix initialized from {reason}. Target `{run.target}` is queued for Recon, Knowledge Base, "
            "Vector Store, Researcher, Developer, Executor, and Report specialist flow."
        )

    def _message(self, db: Session, run_id: str, role: str, author: str, content: str, metadata: dict[str, Any] | None = None) -> RunMessage:
        message = RunMessage(run_id=run_id, role=role, author=author, content=content, metadata_json=metadata or {})
        db.add(message)
        db.flush()
        return message

    def _write_memory(self, db: Session, run: WorkspaceRun, reason: str) -> None:
        try:
            self.memory.write(
                DenseMemoryRecord(
                    mode="phase",
                    run_id=run.id,
                    phase="vantix-scheduler",
                    objective=run.objective,
                    done=[f"scheduler {reason}"],
                    next_action="continue specialist workflow",
                    context=[run.mode, "vantix"],
                ),
                db=db,
            )
        except Exception as exc:  # noqa: BLE001
            self.events.emit(db, run.id, "memory_error", f"Vantix memory write failed: {exc}", level="warning")


class VantixChatService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.scheduler = VantixScheduler()

    def submit(self, *, message: str, run_id: str | None = None, mode: str | None = None, target: str | None = None, metadata: dict[str, Any] | None = None) -> tuple[WorkspaceRun, RunMessage, bool, str]:
        content = message.strip()
        if not content:
            raise ValueError("Message is required")
        if run_id:
            run = self.db.get(WorkspaceRun, run_id)
            if run is None:
                raise ValueError(f"Run not found: {run_id}")
            user_message = self._user_message(run.id, content, metadata or {})
            self.db.add(OperatorNote(run_id=run.id, content=content, author="operator", applies_to="chat"))
            status = self.scheduler.replan(self.db, run, reason="chat-guidance")
            self.db.commit()
            self.db.refresh(run)
            self.db.refresh(user_message)
            return run, user_message, False, status

        resolved_target = target or extract_target(content)
        if not resolved_target:
            raise ValueError("A target is required when starting a Vantix run from chat")
        resolved_mode = mode or "pentest"
        engagement = Engagement(
            name=f"Vantix: {resolved_target}",
            mode=resolved_mode,
            target=resolved_target,
            ruleset="authorized-assessment",
            status="active",
            tags=[resolved_mode, "vantix"],
            metadata_json={"created_from": "chat"},
        )
        self.db.add(engagement)
        self.db.flush()
        run = RunService(self.db).create_run(
            engagement_id=engagement.id,
            objective=content,
            target=resolved_target,
            ports=[],
            services=[],
            tags=[resolved_mode, "vantix"],
            config={"created_from": "chat", "scheduler": "vantix"},
        )
        user_message = self._user_message(run.id, content, metadata or {})
        status = self.scheduler.bootstrap(self.db, run, reason="chat")
        self.db.commit()
        self.db.refresh(run)
        self.db.refresh(user_message)
        return run, user_message, True, status

    def _user_message(self, run_id: str, content: str, metadata: dict[str, Any]) -> RunMessage:
        message = RunMessage(run_id=run_id, role="user", author="operator", content=content, metadata_json=metadata)
        self.db.add(message)
        self.db.flush()
        return message


def extract_target(message: str) -> str:
    match = TARGET_RE.search(message)
    return match.group(1).rstrip(".,;") if match else ""


def vector_from_fact(fact: Fact) -> dict[str, Any]:
    meta = fact.metadata_json or {}
    return {
        "id": fact.id,
        "title": str(meta.get("title") or fact.value or "Candidate vector"),
        "summary": str(meta.get("summary") or ""),
        "source": str(meta.get("source") or fact.source or "manual"),
        "confidence": float(fact.confidence or meta.get("confidence") or 0.0),
        "severity": str(meta.get("severity") or "info"),
        "status": str(meta.get("status") or "candidate"),
        "evidence": str(meta.get("evidence") or ""),
        "next_action": str(meta.get("next_action") or ""),
        "metadata": meta,
        "created_at": fact.created_at,
    }


def create_vector_fact(db: Session, run_id: str, payload: dict[str, Any]) -> Fact:
    metadata = dict(payload.get("metadata") or {})
    metadata.update(
        {
            "title": payload.get("title", "Candidate vector"),
            "summary": payload.get("summary", ""),
            "source": payload.get("source", "manual"),
            "severity": payload.get("severity", "info"),
            "status": payload.get("status", "candidate"),
            "evidence": payload.get("evidence", ""),
            "next_action": payload.get("next_action", ""),
        }
    )
    fact = Fact(
        run_id=run_id,
        source=str(payload.get("source", "manual")),
        kind="vector",
        value=str(payload.get("title", "Candidate vector")),
        confidence=float(payload.get("confidence", 0.5)),
        tags=["vantix", "vector", str(payload.get("status", "candidate"))],
        metadata_json=metadata,
    )
    db.add(fact)
    db.flush()
    return fact


def summarize_terminal(events: list[Any], limit: int = 20) -> str:
    terminal = [event.message for event in events if event.event_type == "terminal"]
    if not terminal:
        return ""
    return "\n".join(terminal[-limit:])


def recent_learning_for_run(run: WorkspaceRun, limit: int = 5) -> list[dict[str, Any]]:
    return LearningService().retrieve_for_run(
        mode=run.mode,
        query=run.objective or run.target or run.mode,
        services=run.config_json.get("services", []),
        ports=run.config_json.get("ports", []),
        tags=run.config_json.get("tags", []),
    )[:limit]
