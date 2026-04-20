from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from secops.config import settings
from secops.models import Action, AgentSession, Engagement, Fact, OperatorNote, RunMessage, Task, WorkspaceRun
from secops.services.events import RunEventService
from secops.services.phase_state import RunPhaseService
from secops.services.learning import LearningService
from secops.services.memory_writer import DenseMemoryRecord, MemoryWriteService
from secops.services.run_service import RunService
from secops.services.skills import SkillApplicationService
from secops.services.storage import StorageLayout

TARGET_RE = re.compile(r"(?i)\b((?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|https?://[a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+|[a-z0-9][a-z0-9.-]+\.[a-z]{2,})(?=\s|$|[,.;])")
QUICK_SCAN_RE = re.compile(r"(?i)\bquick(?:\s|-)?scan\b")
NEW_ENGAGEMENT_RE = re.compile(r"(?i)\b(start|create|open|launch)\b.{0,24}\b(new)\b.{0,24}\b(engagement|run)\b")
ACTION_INTENT_RE = re.compile(r"(?i)\b(run|scan|recon|enumerate|exploit|validate|attack|test|assess|pentest)\b")

SPECIALIST_TASKS = [
    ("flow-initialization", "Orchestrator", "Normalize target, objective, scope, and run state."),
    ("source-intake", "Source Intake", "Resolve source input for white-box analysis."),
    ("source-analysis", "Source Analysis", "Run source-level analysis and extract findings."),
    ("vantix-recon", "Vantix Recon", "Collect low-noise service, port, and target facts."),
    ("browser-assessment", "Browser Assessment", "Explore in-scope web application behavior and collect browser-native evidence."),
    ("knowledge-load", "Knowledge Base", "Load dense memory, learning hits, tool guidance, and prior cases."),
    ("vector-store", "Vector Store", "Rank similar cases and candidate attack patterns."),
    ("research", "Researcher", "Query CVE, exploit, and vulnerability intelligence."),
    ("planning", "Orchestrator Planning", "Select next action and branch between recon, development, execution, or report."),
    ("development", "Developer", "Prepare validation helpers, payload notes, or exploit implementation guidance."),
    ("execution", "Executor", "Run the selected vector through current execution controls."),
    ("reporting", "Vantix Report", "Summarize evidence, artifacts, validated findings, and next steps."),
]

INITIAL_TASKS = [
    ("flow-initialization", "Orchestrator", "Normalize target, objective, scope, and run state."),
    ("source-intake", "Source Intake", "Resolve source input for white-box analysis."),
    ("source-analysis", "Source Analysis", "Run source-level analysis and extract findings."),
    ("vantix-recon", "Vantix Recon", "Collect low-noise service, port, and target facts."),
]

ROLE_NAMES = {
    "orchestrator": "Orchestrator",
    "recon": "Vantix Recon",
    "browser": "Browser Analyst",
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
        self.phases = RunPhaseService()

    def bootstrap(self, db: Session, run: WorkspaceRun, *, reason: str = "chat") -> str:
        scan_profile = str((run.config_json or {}).get("scan_profile", "full")).lower()
        quick_scan = scan_profile == "quick"
        self._seed_tasks(db, run, initial_only=True)
        self._seed_agents(db, run, initial_only=True)
        self._seed_initial_vector(db, run)
        self._set_agent_states(db, run, current_role="recon")
        self.phases.initialize(run, reason=reason)
        db.flush()
        self.skills.apply_to_run(db, run)
        self._message(
            db,
            run.id,
            "orchestrator",
            "Vantix",
            self._orchestrator_summary(run, reason, quick_scan=quick_scan),
            {"reason": reason, "scan_profile": scan_profile},
        )
        self.events.emit(db, run.id, "scheduler", "Vantix scheduler initialized", payload={"reason": reason, "roles": list(ROLE_NAMES)})
        self._write_memory(db, run, reason)
        return "scheduler-initialized"

    def replan(self, db: Session, run: WorkspaceRun, *, reason: str = "chat-guidance") -> str:
        self._seed_tasks(db, run, initial_only=True)
        self._seed_agents(db, run, initial_only=True)
        self._seed_initial_vector(db, run)
        target_phase = "development" if reason == "vector-selected" else "planning"
        active_role = "developer" if reason == "vector-selected" else "orchestrator"
        self._set_agent_states(db, run, current_role=active_role)
        self.phases.transition(run, target_phase, reason=reason)
        db.flush()
        self.skills.apply_to_run(db, run)
        self._message(db, run.id, "orchestrator", "Vantix", f"Replan queued from {reason}. Current target: {run.target or 'unknown'}. Objective remains: {run.objective}", {"reason": reason})
        self.events.emit(db, run.id, "scheduler", "Vantix replan requested", payload={"reason": reason})
        self._write_memory(db, run, reason)
        return "replan-queued"

    def expand_after_quick_scan_approval(self, db: Session, run: WorkspaceRun) -> str:
        self._seed_tasks(db, run, initial_only=True)
        self._seed_agents(db, run, initial_only=True)
        self.skills.apply_to_run(db, run)
        self.events.emit(
            db,
            run.id,
            "scheduler",
            "Quick scan approved for full continuation",
            payload={"scan_profile": (run.config_json or {}).get("scan_profile", "full")},
        )
        return "quick-scan-expanded"

    def _seed_tasks(self, db: Session, run: WorkspaceRun, *, initial_only: bool = False) -> None:
        existing = {task.kind: task for task in db.execute(select(Task).where(Task.run_id == run.id)).scalars().all()}
        max_sequence = max((task.sequence for task in existing.values()), default=0)
        next_sequence = max_sequence + 1
        task_list = INITIAL_TASKS if initial_only else SPECIALIST_TASKS
        for kind, name, description in task_list:
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

    def _seed_agents(self, db: Session, run: WorkspaceRun, *, initial_only: bool = False) -> None:
        paths = self.storage.for_workspace(run.workspace_id)
        existing = {agent.role for agent in db.execute(select(AgentSession).where(AgentSession.run_id == run.id)).scalars().all()}
        roles = ["orchestrator", "recon"] if initial_only else list(ROLE_NAMES.keys())
        for role in roles:
            name = ROLE_NAMES[role]
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

    def _set_agent_states(self, db: Session, run: WorkspaceRun, *, current_role: str) -> None:
        agents = db.execute(select(AgentSession).where(AgentSession.run_id == run.id)).scalars().all()
        for agent in agents:
            agent.status = "running" if agent.role == current_role else "pending"

    def _seed_initial_vector(self, db: Session, run: WorkspaceRun) -> None:
        # Demo bootstrap vectors are intentionally disabled. Vectors should come from real run evidence.
        return

    def _orchestrator_summary(self, run: WorkspaceRun, reason: str, *, quick_scan: bool = False) -> str:
        if quick_scan:
            return (
                f"Vantix initialized from {reason}. Target `{run.target}` is queued for Recon-only quick scan. "
                "You can continue with researcher/developer/executor/report flow after recon completes."
            )
        return (
            f"Vantix initialized from {reason}. Target `{run.target}` is queued for phased specialist workflow. "
            "Recon and orchestration start immediately; browser, research, developer, executor, and report roles activate as the workflow reaches them."
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
        metadata = metadata or {}
        source_input = _normalize_source_input(metadata.get("source_input"))
        force_new = bool(metadata.get("start_new_run"))
        if run_id:
            run = self.db.get(WorkspaceRun, run_id)
            if run is None:
                raise ValueError(f"Run not found: {run_id}")
            explicit_target = target or extract_target(content)
            if not force_new and not _should_start_new_engagement(content, run, explicit_target=explicit_target):
                run.objective = content
                cfg = dict(run.config_json or {})
                if source_input:
                    cfg["source_input"] = source_input
                run.config_json = cfg
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
        if run_id:
            current = self.db.get(WorkspaceRun, run_id)
            resolved_mode = mode or (current.mode if current is not None else "pentest")
        else:
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
            config={
                "created_from": "chat",
                "scheduler": "vantix",
                "scan_profile": "quick" if is_quick_scan_request(content) else "full",
                "source_input": source_input,
            },
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


def is_quick_scan_request(message: str) -> bool:
    return bool(QUICK_SCAN_RE.search(message or ""))


def _should_start_new_engagement(message: str, current_run: WorkspaceRun, *, explicit_target: str = "") -> bool:
    text = message or ""
    if NEW_ENGAGEMENT_RE.search(text):
        return True
    new_target = (explicit_target or "").strip()
    old_target = (current_run.target or "").strip()
    if new_target and old_target and new_target != old_target:
        return True
    terminal = current_run.status in {"completed", "cancelled", "failed"}
    if terminal and new_target:
        if not old_target or new_target != old_target:
            return True
        if ACTION_INTENT_RE.search(text):
            return True
    if terminal and ACTION_INTENT_RE.search(text) and not current_run.objective:
        return True
    return False


def _vector_score(meta: dict[str, Any], confidence: float) -> float:
    evidence_quality = float(meta.get("evidence_quality", 0.5))
    source_credibility = float(meta.get("source_credibility", 0.5))
    novelty = float(meta.get("novelty", 0.5))
    prereq = float(meta.get("prerequisites_satisfied", 0.5))
    noise_penalty = float(meta.get("noise_level_score", 0.4))
    score = (
        confidence * 0.40
        + evidence_quality * 0.20
        + source_credibility * 0.15
        + novelty * 0.15
        + prereq * 0.20
        - noise_penalty * 0.10
    )
    return max(0.0, round(score, 4))


def _normalize_source_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"type": "none"}
    source_type = str(value.get("type", "none")).strip().lower()
    if source_type not in {"none", "github", "local", "upload"}:
        source_type = "none"
    payload = {"type": source_type}
    if source_type == "github":
        github = value.get("github") if isinstance(value.get("github"), dict) else {}
        payload["github"] = {"url": str(github.get("url", "")).strip(), "ref": str(github.get("ref", "")).strip()}
    elif source_type == "local":
        local = value.get("local") if isinstance(value.get("local"), dict) else {}
        payload["local"] = {"path": str(local.get("path", "")).strip()}
    elif source_type == "upload":
        upload = value.get("upload") if isinstance(value.get("upload"), dict) else {}
        payload["upload"] = {"staged_upload_id": str(upload.get("staged_upload_id", "")).strip()}
    return payload


def vector_from_fact(fact: Fact) -> dict[str, Any]:
    meta = fact.metadata_json or {}
    confidence = float(fact.confidence or meta.get("confidence") or 0.0)
    score = _vector_score(meta, confidence)
    return {
        "id": fact.id,
        "title": str(meta.get("title") or fact.value or "Candidate vector"),
        "summary": str(meta.get("summary") or ""),
        "source": str(meta.get("source") or fact.source or "manual"),
        "confidence": confidence,
        "severity": str(meta.get("severity") or "info"),
        "status": str(meta.get("status") or "candidate"),
        "evidence": str(meta.get("evidence") or ""),
        "next_action": str(meta.get("next_action") or ""),
        "metadata": {**meta, "score": score},
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
            "remediation": payload.get("remediation", ""),
            "evidence_quality": float(payload.get("evidence_quality", 0.5)),
            "source_credibility": float(payload.get("source_credibility", 0.5)),
            "novelty": float(payload.get("novelty", 0.5)),
            "noise_level_score": float(payload.get("noise_level_score", 0.4)),
            "prerequisites_satisfied": float(payload.get("prerequisites_satisfied", 0.5)),
            "provenance": {
                "facts": list(payload.get("facts") or []),
                "cves": list(payload.get("cves") or []),
                "learning_hits": list(payload.get("learning_hits") or []),
                "operator_notes": list(payload.get("operator_notes") or []),
            },
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


def build_planning_bundle(db: Session, run: WorkspaceRun) -> dict[str, Any]:
    from secops.services.skills import list_attack_chains

    vectors = [vector_from_fact(fact) for fact in db.execute(select(Fact).where(Fact.run_id == run.id, Fact.kind == "vector")).scalars().all()]
    vectors = sorted(vectors, key=lambda row: float((row.get("metadata") or {}).get("score", 0.0)), reverse=True)
    chains = list_attack_chains(db, run.id)
    chains = sorted(chains, key=lambda row: int(row.get("score") or 0), reverse=True)
    missing_evidence: list[str] = []
    if not vectors:
        missing_evidence.append("No vectors available; add candidate vectors from recon/CVE/learning evidence.")
    if not chains:
        missing_evidence.append("No attack chains available; add chain steps with preconditions and proof requirements.")
    for vector in vectors[:5]:
        if not vector.get("evidence"):
            missing_evidence.append(f"Vector '{vector.get('title')}' has missing evidence details.")
    rationale = [
        {
            "vector_id": row["id"],
            "score": (row.get("metadata") or {}).get("score", 0.0),
            "why": "weighted by confidence/evidence/credibility/novelty/prerequisites minus noise",
        }
        for row in vectors[:5]
    ]
    return {
        "run_id": run.id,
        "workflow_status": run.status,
        "best_vectors": vectors[:5],
        "best_chains": chains[:5],
        "ranking_rationale": rationale,
        "missing_evidence": sorted(set(missing_evidence)),
    }
