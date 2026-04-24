from __future__ import annotations

import json
import time
import mimetypes
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from secops.config import settings
from secops.db import get_db
from secops.models import (
    AgentSession,
    ApprovalRequest,
    Artifact,
    BusEvent,
    Fact,
    Finding,
    OperatorNote,
    ProviderConfig,
    RunEvent,
    RunMessage,
    RunMetric,
    Task,
    WorkerLease,
    WorkerRuntimeStatus,
    WorkflowExecution,
    WorkflowPhaseRun,
    WorkspaceRun,
)
from secops.mode_profiles import get_mode_profile
from secops.schemas import (
    AgentSessionRead,
    AttackGraphRead,
    AttackChainCreate,
    AttackChainRead,
    ApprovalRead,
    ContextBundleRead,
    FactRead,
    HandoffRead,
    OperatorNoteCreate,
    OperatorNoteRead,
    RunControlResponse,
    RunCreate,
    RunValidationConfigUpdate,
    RunGraphRead,
    RunLearningRead,
    RunRead,
    RunEventRead,
    RunMessageRead,
    TaskRead,
    TerminalRead,
    ArtifactRead,
    BrowserStateRead,
    BusEventRead,
    VectorCreate,
    VectorRead,
    RunResultsRead,
    RunSkillApplicationRead,
    RunPhaseRead,
    WorkflowStateRead,
    FindingPromotionCreate,
    FindingRead,
    FindingReviewCreate,
    RunProviderRouteCreate,
    PlanningBundleRead,
    ReplayStateRead,
)
from secops.security import require_csrf, require_user
from secops.attack_graph.service import AttackGraphService
from secops.services.context_builder import ContextBuilder
from secops.services.execution import execution_manager
from secops.replay.manifest import build_replay_manifest
from secops.services.events import canonical_event_view, normalize_event_payload
from secops.services.finding_promotion import FindingPromotionService
from secops.services.finding_review import FindingReviewService, ReviewError
from secops.services.learning import LearningService
from secops.services.phase_state import RunPhaseService
from secops.services.storage import StorageLayout
from secops.services.run_service import RunService
from secops.services.skills import (
    SkillApplicationService,
    attack_chain_from_fact,
    build_handoff,
    create_attack_chain_fact,
    list_attack_chains,
)
from secops.services.vantix import build_planning_bundle, create_vector_fact, summarize_terminal, vector_from_fact, VantixScheduler


router = APIRouter(prefix="/api/v1/runs", tags=["runs"], dependencies=[Depends(require_user("operator")), Depends(require_csrf)])


WORKFLOW_SPECIALIST_MAP = {
    "context-bootstrap": {"tasks": ["flow-initialization"], "agents": ["orchestrator"]},
    "source-intake": {"tasks": ["source-intake"], "agents": ["developer"]},
    "source-analysis": {"tasks": ["source-analysis"], "agents": ["developer"]},
    "learning-recall": {"tasks": ["knowledge-load"], "agents": ["knowledge_base"]},
    "recon-sidecar": {"tasks": ["vantix-recon"], "agents": ["recon"]},
    "browser-assessment": {"tasks": ["browser-assessment"], "agents": ["browser"]},
    "cve-analysis": {"tasks": ["research", "vector-store"], "agents": ["researcher", "vector_store"]},
    "orchestrate": {"tasks": ["planning"], "agents": ["orchestrator"]},
    "report": {"tasks": ["reporting"], "agents": ["reporter"]},
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _seconds_between(start: datetime | None, end: datetime | None) -> float | None:
    s = _as_utc(start)
    e = _as_utc(end)
    if s is None or e is None:
        return None
    return max(0.0, (e - s).total_seconds())


def _blocked_reason_class(reason: str) -> str:
    lower = str(reason or "").strip().lower()
    if not lower:
        return "unknown"
    if "scope" in lower or "out of scope" in lower or "denied range" in lower:
        return "scope"
    if "approval" in lower:
        return "approval"
    if "policy" in lower:
        return "policy"
    if "timeout" in lower:
        return "timeout"
    if "auth" in lower:
        return "auth"
    return "other"


def _serialize_event(event: RunEvent) -> dict[str, Any]:
    return canonical_event_view(event)


def _metric_sum(metric_rows: list[RunMetric], name: str) -> float:
    total = 0.0
    for row in metric_rows:
        if row.metric_name == name:
            total += float(row.metric_value or 0.0)
    return total


def _backfill_specialist_status(db: Session, run_id: str) -> None:
    latest: dict[str, WorkflowPhaseRun] = {}
    rows = (
        db.query(WorkflowPhaseRun)
        .filter(WorkflowPhaseRun.run_id == run_id)
        .order_by(WorkflowPhaseRun.phase_name.asc(), WorkflowPhaseRun.attempt.desc())
        .all()
    )
    for row in rows:
        latest.setdefault(row.phase_name, row)

    for phase_name, phase in latest.items():
        mapping = WORKFLOW_SPECIALIST_MAP.get(phase_name)
        if not mapping:
            continue
        status_map = {
            "completed": "completed",
            "failed": "failed",
            "blocked": "blocked",
            "claimed": "running",
            "retrying": "running",
            "pending": "pending",
            "waiting": "pending",
        }
        mapped_status = status_map.get(phase.status, "pending")
        if mapped_status == "pending":
            continue
        for task_kind in mapping["tasks"]:
            task = (
                db.query(Task)
                .filter(Task.run_id == run_id, Task.kind == task_kind)
                .order_by(Task.created_at.desc())
                .first()
            )
            if task is not None:
                task.status = mapped_status
        for role in mapping["agents"]:
            agent = (
                db.query(AgentSession)
                .filter(AgentSession.run_id == run_id, AgentSession.role == role)
                .order_by(AgentSession.started_at.desc())
                .first()
            )
            if agent is not None:
                agent.status = mapped_status


@router.post("", response_model=RunRead)
def create_run(payload: RunCreate, db: Session = Depends(get_db)) -> WorkspaceRun:
    service = RunService(db)
    config = dict(payload.config or {})
    if payload.quick:
        config["scan_profile"] = "quick"
    try:
        run = service.create_run(
            engagement_id=payload.engagement_id,
            objective=payload.objective,
            target=payload.target,
            ports=payload.ports,
            services=payload.services,
            tags=payload.tags,
            config=config,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return run


@router.get("", response_model=list[RunRead])
def list_runs(limit: int = 100, db: Session = Depends(get_db)) -> list[WorkspaceRun]:
    limit = max(1, min(int(limit), 500))
    return db.query(WorkspaceRun).order_by(WorkspaceRun.started_at.desc()).limit(limit).all()


@router.get("/compare")
def compare_runs(a: str = Query(...), b: str = Query(...), db: Session = Depends(get_db)) -> dict:
    """P3-6 — structured diff between two runs over findings, phases, vectors."""
    run_a = db.get(WorkspaceRun, a)
    run_b = db.get(WorkspaceRun, b)
    if run_a is None or run_b is None:
        raise HTTPException(status_code=404, detail="Run not found")

    def _finding_map(run_id: str) -> dict[str, dict]:
        rows = db.query(Finding).filter(Finding.run_id == run_id).all()
        out: dict[str, dict] = {}
        for f in rows:
            key = f.fingerprint or f"id:{f.id}"
            out[key] = {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "disposition": f.disposition,
                "fingerprint": f.fingerprint,
            }
        return out

    def _severity_histogram(findings: dict[str, dict]) -> dict[str, int]:
        hist: dict[str, int] = {}
        for row in findings.values():
            sev = str(row.get("severity") or "info")
            hist[sev] = hist.get(sev, 0) + 1
        return hist

    def _phase_durations(run_id: str) -> dict[str, float]:
        rows = db.query(WorkflowPhaseRun).filter(WorkflowPhaseRun.run_id == run_id).all()
        out: dict[str, float] = {}
        for phase in rows:
            started = _as_utc(getattr(phase, "started_at", None))
            finished = _as_utc(getattr(phase, "completed_at", None))
            if started is None or finished is None:
                continue
            dur = max(0.0, (finished - started).total_seconds())
            name = str(phase.phase_name or "")
            out[name] = max(out.get(name, 0.0), round(dur, 3))
        return out

    def _vector_count(run_id: str) -> int:
        return db.query(Fact).filter(Fact.run_id == run_id, Fact.kind == "vector").count()

    fa, fb = _finding_map(a), _finding_map(b)
    keys_a, keys_b = set(fa), set(fb)
    only_a = sorted(keys_a - keys_b)
    only_b = sorted(keys_b - keys_a)
    common = sorted(keys_a & keys_b)
    common_changed: list[dict] = []
    for key in common:
        left, right = fa[key], fb[key]
        changed = {
            k: {"a": left.get(k), "b": right.get(k)}
            for k in ("severity", "status", "disposition")
            if left.get(k) != right.get(k)
        }
        if changed:
            common_changed.append({"fingerprint": key, "changes": changed, "title": left.get("title")})

    pa, pb = _phase_durations(a), _phase_durations(b)
    phase_diff = []
    for name in sorted(set(pa) | set(pb)):
        phase_diff.append(
            {
                "phase_name": name,
                "duration_a_seconds": pa.get(name),
                "duration_b_seconds": pb.get(name),
                "delta_seconds": round((pb.get(name) or 0.0) - (pa.get(name) or 0.0), 3),
            }
        )

    return {
        "run_a": {"id": run_a.id, "status": run_a.status, "started_at": _as_utc(run_a.started_at).isoformat() if run_a.started_at else None},
        "run_b": {"id": run_b.id, "status": run_b.status, "started_at": _as_utc(run_b.started_at).isoformat() if run_b.started_at else None},
        "findings": {
            "only_in_a": [fa[k] for k in only_a],
            "only_in_b": [fb[k] for k in only_b],
            "changed": common_changed,
            "severity_a": _severity_histogram(fa),
            "severity_b": _severity_histogram(fb),
        },
        "phases": phase_diff,
        "vectors": {
            "count_a": _vector_count(a),
            "count_b": _vector_count(b),
        },
    }


@router.get("/{run_id}", response_model=RunRead)
def get_run(run_id: str, db: Session = Depends(get_db)) -> WorkspaceRun:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.get("/{run_id}/source-status")
def get_run_source_status(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    cfg = dict(run.config_json or {})
    return {
        "run_id": run_id,
        "source_input": cfg.get("source_input", {}),
        "source_context": cfg.get("source_context", {}),
    }


@router.post("/{run_id}/resume", response_model=RunRead)
def resume_run(run_id: str, db: Session = Depends(get_db)) -> WorkspaceRun:
    service = RunService(db)
    try:
        return service.resume_run(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{run_id}/tasks", response_model=list[TaskRead])
def list_run_tasks(run_id: str, db: Session = Depends(get_db)) -> list[Task]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(Task).filter(Task.run_id == run_id).order_by(Task.sequence.asc()).all()


@router.get("/{run_id}/context", response_model=ContextBundleRead)
def get_run_context(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    profile = get_mode_profile(run.mode)
    builder = ContextBuilder()
    return builder.build(
        profile=profile,
        target=run.target,
        ports=run.config_json.get("ports", []),
        services=run.config_json.get("services", []),
        extra_tags=run.config_json.get("tags", []),
    )


@router.get("/{run_id}/artifacts", response_model=list[ArtifactRead])
def list_run_artifacts(run_id: str, db: Session = Depends(get_db)) -> list[Artifact]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(Artifact).filter(Artifact.run_id == run_id).all()


def _is_allowed_runtime_path(path: Path, run: WorkspaceRun) -> bool:
    allowed_roots = {
        settings.runtime_root.resolve(),
        settings.reports_root.resolve(),
        (settings.runtime_root / "runs" / run.workspace_id).resolve(),
    }
    resolved = path.resolve()
    for root in allowed_roots:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _is_registered_run_artifact(path: Path, run_id: str, db: Session) -> bool:
    artifact_rows = db.query(Artifact.path).filter(Artifact.run_id == run_id).all()
    for row in artifact_rows:
        raw_path = str(row[0] or "").strip()
        if not raw_path:
            continue
        try:
            artifact_resolved = Path(raw_path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            continue
        if artifact_resolved == path:
            return True
    return False


@router.get("/{run_id}/file")
def open_run_file(run_id: str, path: str = Query(min_length=1), db: Session = Depends(get_db)):
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = settings.runtime_root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="File not found") from exc
    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    if not _is_allowed_runtime_path(resolved, run):
        raise HTTPException(status_code=403, detail="File path not allowed")
    if not _is_registered_run_artifact(resolved, run_id, db):
        raise HTTPException(status_code=403, detail="File is not a registered run artifact")
    media_type = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
    return FileResponse(path=str(resolved), media_type=media_type, filename=resolved.name)


@router.post("/{run_id}/start", response_model=RunControlResponse)
def start_run(run_id: str, db: Session = Depends(get_db)) -> RunControlResponse:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    message = execution_manager.start(run_id)
    return RunControlResponse(run_id=run_id, status=run.status, message=message)


@router.post("/{run_id}/pause", response_model=RunControlResponse)
def pause_run(run_id: str, db: Session = Depends(get_db)) -> RunControlResponse:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    message = execution_manager.pause(run_id)
    return RunControlResponse(run_id=run_id, status=run.status, message=message)


@router.post("/{run_id}/cancel", response_model=RunControlResponse)
def cancel_run(run_id: str, db: Session = Depends(get_db)) -> RunControlResponse:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    message = execution_manager.cancel(run_id)
    return RunControlResponse(run_id=run_id, status=run.status, message=message)


@router.post("/{run_id}/retry", response_model=RunControlResponse)
def retry_run(run_id: str, db: Session = Depends(get_db)) -> RunControlResponse:
    service = RunService(db)
    try:
        run = service.retry_run(run_id, replan=False)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    message = execution_manager.start(run_id)
    return RunControlResponse(run_id=run_id, status=run.status, message=message)


@router.post("/{run_id}/replan", response_model=RunControlResponse)
def replan_run(run_id: str, db: Session = Depends(get_db)) -> RunControlResponse:
    service = RunService(db)
    try:
        run = service.retry_run(run_id, replan=True)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    message = execution_manager.start(run_id)
    return RunControlResponse(run_id=run_id, status=run.status, message=f"Replan requested. {message}")


@router.get("/{run_id}/graph", response_model=RunGraphRead)
def get_run_graph(run_id: str, db: Session = Depends(get_db)) -> RunGraphRead:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    _backfill_specialist_status(db, run_id)
    tasks = db.query(Task).filter(Task.run_id == run_id).order_by(Task.sequence.asc()).all()
    agents = db.query(AgentSession).filter(AgentSession.run_id == run_id).order_by(AgentSession.started_at.asc()).all()
    approvals = db.query(ApprovalRequest).filter(ApprovalRequest.run_id == run_id).order_by(ApprovalRequest.created_at.asc()).all()
    phase = RunPhaseService().refresh(db, run, reason="graph-read")
    db.commit()
    return RunGraphRead(run_id=run_id, status=run.status, phase=phase, tasks=tasks, agents=agents, approvals=approvals)


@router.get("/{run_id}/agents", response_model=list[AgentSessionRead])
def list_run_agents(run_id: str, db: Session = Depends(get_db)) -> list[AgentSession]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(AgentSession).filter(AgentSession.run_id == run_id).order_by(AgentSession.started_at.asc()).all()


@router.get("/{run_id}/attack-graph", response_model=AttackGraphRead)
def get_attack_graph(run_id: str, sync: bool = True, db: Session = Depends(get_db)) -> dict[str, Any]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    payload = AttackGraphService().read_run(db, run, sync=sync)
    if sync:
        db.commit()
    return payload


@router.get("/{run_id}/facts", response_model=list[FactRead])
def list_run_facts(run_id: str, db: Session = Depends(get_db)) -> list[Fact]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(Fact).filter(Fact.run_id == run_id).order_by(Fact.created_at.asc()).all()


@router.get("/{run_id}/events", response_model=list[RunEventRead])
def list_run_events(
    run_id: str,
    since_sequence: int = 0,
    limit: int = 500,
    db: Session = Depends(get_db),
) -> list[dict]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    limit = max(1, min(int(limit), 2000))
    q = db.query(RunEvent).filter(RunEvent.run_id == run_id)
    if since_sequence > 0:
        q = q.filter(RunEvent.sequence > int(since_sequence))
    rows = q.order_by(RunEvent.sequence.asc()).limit(limit).all()
    return [_serialize_event(row) for row in rows]


@router.get("/{run_id}/terminal", response_model=TerminalRead)
def get_run_terminal(
    run_id: str,
    since_sequence: int = 0,
    limit: int = 500,
    tail: bool = False,
    db: Session = Depends(get_db),
) -> TerminalRead:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    limit = max(1, min(int(limit), 2000))
    q = db.query(RunEvent).filter(RunEvent.run_id == run_id, RunEvent.event_type == "terminal")
    if since_sequence > 0:
        q = q.filter(RunEvent.sequence > int(since_sequence))
    if tail:
        events = list(reversed(q.order_by(RunEvent.sequence.desc()).limit(limit).all()))
    else:
        events = q.order_by(RunEvent.sequence.asc()).limit(limit).all()
    content = "\n".join(event.message for event in events)
    last_sequence = int(events[-1].sequence) if events else int(since_sequence or 0)
    return TerminalRead(run_id=run_id, content=content, last_sequence=last_sequence)


@router.get("/{run_id}/approvals", response_model=list[ApprovalRead])
def list_run_approvals(run_id: str, db: Session = Depends(get_db)) -> list[ApprovalRequest]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(ApprovalRequest).filter(ApprovalRequest.run_id == run_id).order_by(ApprovalRequest.created_at.asc()).all()


@router.post("/{run_id}/operator-notes", response_model=OperatorNoteRead)
def create_operator_note(
    run_id: str,
    payload: OperatorNoteCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> OperatorNote:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    # PRA-044: author comes from the session, never from the client body.
    auth = getattr(request.state, "auth", None)
    author = auth.username if auth is not None else "operator"
    classification = (payload.classification or "unrestricted").lower()
    if classification not in {"unrestricted", "internal", "sensitive"}:
        raise HTTPException(status_code=400, detail="Invalid classification")
    note = OperatorNote(
        run_id=run_id,
        content=payload.content,
        author=author,
        applies_to=payload.applies_to,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    paths = StorageLayout().for_workspace(run.workspace_id)
    note_path = paths.notes / f"{note.created_at.strftime('%Y%m%d_%H%M%S')}_{note.id}.md"
    note_path.write_text(
        f"# Operator Note\n\n- Author: {note.author}\n- Classification: {classification}\n- Applies To: {note.applies_to}\n- Content: {note.content}\n",
        encoding="utf-8",
    )
    return note


@router.get("/{run_id}/notes", response_model=list[OperatorNoteRead])
def list_operator_notes(run_id: str, db: Session = Depends(get_db)) -> list[OperatorNote]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(OperatorNote).filter(OperatorNote.run_id == run_id).order_by(OperatorNote.created_at.asc()).all()


@router.get("/{run_id}/learning", response_model=RunLearningRead)
def get_run_learning(run_id: str, db: Session = Depends(get_db)) -> RunLearningRead:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    results = LearningService().retrieve_for_run(
        mode=run.mode,
        query=run.objective or run.target or run.mode,
        services=run.config_json.get("services", []),
        ports=run.config_json.get("ports", []),
        tags=run.config_json.get("tags", []),
    )
    return RunLearningRead(run_id=run.id, mode=run.mode, results=results)


@router.get("/{run_id}/messages", response_model=list[RunMessageRead])
def list_run_messages(
    run_id: str,
    limit: int = 200,
    db: Session = Depends(get_db),
) -> list[RunMessage]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    limit = max(1, min(int(limit), 1000))
    rows = (
        db.query(RunMessage)
        .filter(RunMessage.run_id == run_id)
        .order_by(RunMessage.created_at.desc())
        .limit(limit)
        .all()
    )
    return list(reversed(rows))


@router.get("/{run_id}/vectors", response_model=list[VectorRead])
def list_run_vectors(run_id: str, db: Session = Depends(get_db)) -> list[dict]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    facts = db.query(Fact).filter(Fact.run_id == run_id, Fact.kind == "vector").order_by(Fact.created_at.asc()).all()
    vectors = [vector_from_fact(fact) for fact in facts]
    vectors.sort(key=lambda row: float((row.get("metadata") or {}).get("score", 0.0)), reverse=True)
    return vectors


@router.get("/{run_id}/phase", response_model=RunPhaseRead)
def get_run_phase(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    phase = RunPhaseService().refresh(db, run, reason="phase-read")
    db.commit()
    return phase


@router.get("/{run_id}/workflow-state", response_model=WorkflowStateRead)
def get_workflow_state(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    workflow = (
        db.query(WorkflowExecution)
        .filter(WorkflowExecution.run_id == run_id)
        .order_by(WorkflowExecution.created_at.desc())
        .first()
    )
    workflow_id = workflow.id if workflow is not None else None
    phases = (
        db.query(WorkflowPhaseRun)
        .filter(WorkflowPhaseRun.run_id == run_id)
        .order_by(WorkflowPhaseRun.phase_name.asc(), WorkflowPhaseRun.attempt.asc())
        .all()
    )
    leases = (
        db.query(WorkerLease)
        .filter(WorkerLease.run_id == run_id)
        .order_by(WorkerLease.created_at.desc())
        .limit(50)
        .all()
    )
    worker_ids = sorted({row.worker_id for row in phases if row.worker_id} | {lease.worker_id for lease in leases if lease.worker_id})
    workers = (
        db.query(WorkerRuntimeStatus)
        .filter(WorkerRuntimeStatus.worker_id.in_(worker_ids))
        .order_by(WorkerRuntimeStatus.heartbeat_at.desc())
        .all()
        if worker_ids
        else []
    )
    # If no run-specific worker has claimed yet, still surface recent runtime workers
    # so the control center does not show a misleading "workers 0".
    if not workers:
        freshness_cutoff = _utc_now().timestamp() - 300.0
        recent_workers = db.query(WorkerRuntimeStatus).order_by(WorkerRuntimeStatus.heartbeat_at.desc()).limit(10).all()
        workers = [
            row
            for row in recent_workers
            if row.heartbeat_at and _as_utc(row.heartbeat_at) is not None and _as_utc(row.heartbeat_at).timestamp() >= freshness_cutoff
        ]
    metric_rows = (
        db.query(RunMetric)
        .filter(RunMetric.run_id == run_id)
        .order_by(RunMetric.created_at.desc())
        .limit(200)
        .all()
    )
    latest_by_phase: dict[str, WorkflowPhaseRun] = {}
    for phase in phases:
        existing = latest_by_phase.get(phase.phase_name)
        if existing is None:
            latest_by_phase[phase.phase_name] = phase
            continue
        existing_key = (int(existing.attempt or 0), _as_utc(existing.updated_at) or _as_utc(existing.created_at) or _utc_now())
        phase_key = (int(phase.attempt or 0), _as_utc(phase.updated_at) or _as_utc(phase.created_at) or _utc_now())
        if phase_key > existing_key:
            latest_by_phase[phase.phase_name] = phase
    blocked_reasons = sorted(
        {
            str((phase.error_json or {}).get("message", "")).strip()
            for phase in latest_by_phase.values()
            if phase.status == "blocked" and str((phase.error_json or {}).get("message", "")).strip()
        }
    )
    approval_rows = (
        db.query(ApprovalRequest)
        .filter(ApprovalRequest.run_id == run_id)
        .order_by(ApprovalRequest.created_at.asc())
        .all()
    )
    retry_count = sum(1 for phase in phases if phase.status == "retrying")
    completed_count = sum(1 for phase in phases if phase.status == "completed")
    blocked_count = sum(1 for phase in phases if phase.status == "blocked")
    active_leases = [lease for lease in leases if lease.status == "active"]
    stale_workers = [worker for worker in workers if worker.status in {"stale", "error"}]
    approval_latencies = [
        (_seconds_between(approval.created_at, approval.updated_at) or 0.0)
        for approval in approval_rows
        if approval.status in {"approved", "rejected"}
    ]
    latest_phase = None
    if workflow is not None:
        latest_phase = (
            db.query(WorkflowPhaseRun)
            .filter(WorkflowPhaseRun.run_id == run_id, WorkflowPhaseRun.phase_name == workflow.current_phase)
            .order_by(WorkflowPhaseRun.attempt.desc(), WorkflowPhaseRun.created_at.desc())
            .first()
        )
    if latest_phase is None and phases:
        latest_phase = max(
            phases,
            key=lambda row: (
                1 if row.status in {"claimed", "retrying", "pending"} else 0,
                row.updated_at or row.created_at,
            ),
        )
    current_phase_duration_seconds = _seconds_between(
        latest_phase.started_at if latest_phase is not None else None,
        latest_phase.completed_at if latest_phase is not None and latest_phase.completed_at is not None else _utc_now(),
    )
    phase_durations: dict[str, float] = {}
    for phase in phases:
        duration = _seconds_between(phase.started_at, phase.completed_at or _utc_now())
        if duration is None:
            continue
        phase_durations[phase.phase_name] = max(float(phase_durations.get(phase.phase_name, 0.0)), round(duration, 3))
    latest_active_lease = active_leases[0] if active_leases else None
    current_claim_age_seconds = (
        (_seconds_between(latest_active_lease.created_at, _utc_now()) or 0.0)
        if latest_active_lease is not None
        else 0.0
    )
    metrics = {
        "workflow_id": workflow_id or "",
        "retry_count": retry_count,
        "completed_count": completed_count,
        "blocked_count": blocked_count,
        "active_lease_count": len(active_leases),
        "active_worker_count": len([worker for worker in workers if worker.status in {"claimed", "running"}]),
        "stale_worker_count": len(stale_workers),
        "latest_heartbeat_at": workers[0].heartbeat_at.isoformat() if workers else "",
        "metric_samples": len(metric_rows),
        "approval_pending_count": len([approval for approval in approval_rows if approval.status == "pending"]),
        "approval_resolved_count": len(approval_latencies),
        "approval_latency_seconds_avg": round(sum(approval_latencies) / len(approval_latencies), 3) if approval_latencies else 0.0,
        "approval_latency_seconds_latest": round(approval_latencies[-1], 3) if approval_latencies else 0.0,
        "current_phase_duration_seconds": round(current_phase_duration_seconds or 0.0, 3),
        "current_claim_age_seconds": round(current_claim_age_seconds, 3),
        "phase_durations_seconds": phase_durations,
        "blocked_reason_classes": sorted({_blocked_reason_class(reason) for reason in blocked_reasons if reason}),
        "stale_claim_recovered_count": int(_metric_sum(metric_rows, "stale_claim_recovered_total")),
        "phase_claimed_total": int(_metric_sum(metric_rows, "phase_claimed_total")),
        "phase_completed_total": int(_metric_sum(metric_rows, "phase_completed_total")),
        "phase_failed_total": int(_metric_sum(metric_rows, "phase_failed_total")),
    }
    return {
        "run_id": run_id,
        "workflow": workflow,
        "phases": phases,
        "leases": leases,
        "workers": workers,
        "blocked_reasons": blocked_reasons,
        "metrics": metrics,
    }


@router.post("/{run_id}/vectors", response_model=VectorRead)
def create_run_vector(run_id: str, payload: VectorCreate, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    fact = create_vector_fact(db, run_id, payload.model_dump())
    execution_manager.events.emit(
        db,
        run_id,
        "vector",
        f"Vector generated: {fact.value}",
        payload={"vector_id": fact.id, "status": (fact.metadata_json or {}).get("status", "candidate"), "source": fact.source},
    )
    db.commit()
    db.refresh(fact)
    return vector_from_fact(fact)


@router.post("/{run_id}/vectors/{vector_id}/select", response_model=VectorRead)
def select_run_vector(run_id: str, vector_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    fact = db.get(Fact, vector_id)
    if fact is None or fact.run_id != run_id or fact.kind != "vector":
        raise HTTPException(status_code=404, detail="Vector not found")
    metadata = dict(fact.metadata_json or {})
    metadata["status"] = "planned"
    metadata["selected_at"] = time.time()
    metadata.setdefault("noise_level", "quiet")
    metadata.setdefault("requires_approval", True)
    metadata.setdefault("scope_check", "required-before-execution")
    metadata.setdefault("safety_notes", "Selected vectors must remain inside authorized scope and require evidence capture.")
    fact.metadata_json = metadata
    fact.tags = sorted(set([*fact.tags, "planned"]))
    execution_manager.events.emit(
        db,
        run_id,
        "vector",
        f"Vector selected: {fact.value}",
        payload={"vector_id": fact.id, "status": metadata["status"], "source": fact.source},
    )
    RunPhaseService().transition(run, "development", reason="vector-selected", details={"vector_id": vector_id})
    VantixScheduler().replan(db, run, reason="vector-selected")
    db.commit()
    db.refresh(fact)
    return vector_from_fact(fact)


@router.get("/{run_id}/findings", response_model=list[FindingRead])
def list_run_findings(run_id: str, db: Session = Depends(get_db)) -> list[Finding]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(Finding).filter(Finding.run_id == run_id).order_by(Finding.created_at.asc()).all()


@router.post("/{run_id}/findings/promote", response_model=FindingRead)
def promote_finding(run_id: str, payload: FindingPromotionCreate, db: Session = Depends(get_db)) -> Finding:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    try:
        finding = FindingPromotionService().promote(db, run, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    RunPhaseService().transition(run, "reporting", reason="finding-promoted", details={"finding_id": finding.id})
    db.commit()
    db.refresh(finding)
    return finding


@router.post("/{run_id}/findings/{finding_id}/review", response_model=FindingRead)
def review_finding(
    run_id: str,
    finding_id: str,
    payload: FindingReviewCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> Finding:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    ctx = getattr(request.state, "auth", None)
    reviewer = getattr(ctx, "username", "") or ""
    if not reviewer:
        raise HTTPException(status_code=401, detail="Reviewer identity not established")
    try:
        finding = FindingReviewService().review(
            db,
            run,
            finding_id,
            reviewer_username=reviewer,
            disposition=payload.disposition,
            note=payload.note,
        )
    except ReviewError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    db.refresh(finding)
    return finding


@router.post("/{run_id}/provider-route", response_model=RunRead)
def set_run_provider_route(run_id: str, payload: RunProviderRouteCreate, db: Session = Depends(get_db)) -> WorkspaceRun:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    config = dict(run.config_json or {})
    provider_id = str(payload.provider_id or "").strip()
    if provider_id:
        provider = db.get(ProviderConfig, provider_id)
        if provider is None:
            raise HTTPException(status_code=404, detail="Provider not found")
        config["provider_id"] = provider.id
        config["runtime_route"] = {"runtime": "provider", "provider_id": provider.id, "provider_type": provider.provider_type}
    else:
        config.pop("provider_id", None)
        config["runtime_route"] = {"runtime": "codex", "provider_id": "", "provider_type": ""}
    run.config_json = config
    SkillApplicationService().apply_to_run(db, run)
    db.commit()
    db.refresh(run)
    return run


@router.post("/{run_id}/validation-config", response_model=RunRead)
def set_run_validation_config(run_id: str, payload: RunValidationConfigUpdate, db: Session = Depends(get_db)) -> WorkspaceRun:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    config = dict(run.config_json or {})
    validation = dict(config.get("validation") or {})
    high_risk = dict(validation.get("high_risk_surfaces") or {})
    if payload.enabled is not None:
        high_risk["enabled"] = bool(payload.enabled)
    if payload.label is not None:
        label = str(payload.label).strip() or "High Risk Surfaces"
        high_risk["label"] = label[:80]
    validation["high_risk_surfaces"] = high_risk
    config["validation"] = validation
    run.config_json = config
    db.commit()
    db.refresh(run)
    return run


@router.get("/{run_id}/results", response_model=RunResultsRead)
def get_run_results(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    findings = db.query(Finding).filter(Finding.run_id == run_id).order_by(Finding.created_at.asc()).all()
    artifacts = db.query(Artifact).filter(Artifact.run_id == run_id).order_by(Artifact.created_at.asc()).all()
    events = db.query(RunEvent).filter(RunEvent.run_id == run_id).order_by(RunEvent.sequence.asc()).all()
    vectors = list_run_vectors(run_id, db)
    report = next((artifact.path for artifact in artifacts if artifact.kind == "report"), None)
    report_json = next((artifact.path for artifact in artifacts if artifact.kind == "report-json"), None)
    comprehensive_report = next((artifact.path for artifact in artifacts if artifact.kind == "comprehensive-report"), None)
    comprehensive_report_json = next((artifact.path for artifact in artifacts if artifact.kind == "comprehensive-report-json"), None)
    artifact_index_path = next((artifact.path for artifact in artifacts if artifact.kind == "artifact-index"), None)
    timeline_csv_path = next((artifact.path for artifact in artifacts if artifact.kind == "timeline-csv"), None)
    executive_summary = ""
    if report_json:
        try:
            summary_payload = json.loads(Path(report_json).read_text(encoding="utf-8"))
            executive_summary = str(summary_payload.get("executive_summary") or "")
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            executive_summary = ""
    return {
        "run_id": run.id,
        "status": run.status,
        "findings": findings,
        "artifacts": artifacts,
        "vectors": vectors,
        "terminal_summary": summarize_terminal(events),
        "report_path": report,
        "report_json_path": report_json,
        "comprehensive_report_path": comprehensive_report,
        "comprehensive_report_json_path": comprehensive_report_json,
        "artifact_index_path": artifact_index_path,
        "timeline_csv_path": timeline_csv_path,
        "executive_summary": executive_summary,
    }


@router.get("/{run_id}/browser-state", response_model=BrowserStateRead)
def get_browser_state(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    artifacts = (
        db.query(Artifact)
        .filter(
            Artifact.run_id == run_id,
            Artifact.kind.in_(
                [
                    "browser-session-summary",
                    "browser-auth-state",
                    "browser-js-signals",
                    "route-discovery",
                    "form-map",
                    "network-summary",
                    "screenshot",
                    "dom-snapshot",
                ]
            ),
        )
        .order_by(Artifact.created_at.asc())
        .all()
    )
    state: dict[str, Any] = {
        "run_id": run_id,
        "status": "idle",
        "entry_url": "",
        "current_url": "",
        "authenticated": "not_attempted",
        "pages_visited": 0,
        "routes_discovered": 0,
        "blocked_actions": [],
        "network_summary": {},
        "route_edges": [],
        "forms": [],
        "session_summary": {},
        "auth_transitions": [],
        "dom_diffs": [],
        "js_signals": [],
        "route_hints": [],
        "screenshots": [],
        "artifacts": [{"kind": item.kind, "path": item.path} for item in artifacts],
    }
    for art in artifacts:
        if art.kind == "screenshot":
            state["screenshots"].append(art.path)
            continue
        if art.kind not in {"browser-session-summary", "browser-auth-state", "browser-js-signals", "route-discovery", "form-map", "network-summary"}:
            continue
        try:
            payload = json.loads(Path(art.path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue
        if art.kind == "browser-session-summary":
            state["status"] = "completed"
            state["entry_url"] = str(payload.get("entry_url") or "")
            state["current_url"] = str(payload.get("current_url") or "")
            state["authenticated"] = str(payload.get("authenticated") or "not_attempted")
            state["pages_visited"] = int(payload.get("pages_visited") or 0)
            state["blocked_actions"] = [str(item) for item in (payload.get("blocked_actions") or [])][:100]
            state["session_summary"] = payload if isinstance(payload, dict) else {}
        elif art.kind == "browser-auth-state":
            state["auth_transitions"] = [item for item in (payload.get("auth_transitions") or []) if isinstance(item, dict)][:40]
            state["dom_diffs"] = [item for item in (payload.get("dom_diffs") or []) if isinstance(item, dict)][:80]
        elif art.kind == "browser-js-signals":
            pages = [item for item in (payload.get("pages") or []) if isinstance(item, dict)][:80]
            signals: list[dict[str, Any]] = []
            hints: list[dict[str, Any]] = []
            for item in pages:
                url = str(item.get("url") or "")
                for signal in item.get("js_signals") or []:
                    if isinstance(signal, dict):
                        signals.append({"url": url, **signal})
                for hint in item.get("route_hints") or []:
                    if str(hint or "").strip():
                        hints.append({"url": url, "hint": str(hint)})
            state["js_signals"] = signals[:80]
            state["route_hints"] = hints[:80]
        elif art.kind == "route-discovery":
            edges = payload.get("edges") or []
            state["route_edges"] = [edge for edge in edges if isinstance(edge, dict)][:300]
            state["routes_discovered"] = len({str(item.get("to") or "") for item in state["route_edges"] if str(item.get("to") or "")})
        elif art.kind == "form-map":
            forms = payload.get("forms") or []
            state["forms"] = [item for item in forms if isinstance(item, dict)][:120]
        elif art.kind == "network-summary":
            state["network_summary"] = payload if isinstance(payload, dict) else {}
    if not state["artifacts"]:
        state["status"] = "not-started"
    return state


@router.get("/{run_id}/skills", response_model=list[RunSkillApplicationRead])
def list_run_skills(run_id: str, db: Session = Depends(get_db)) -> list[dict]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return SkillApplicationService().list_for_run(db, run_id)


@router.post("/{run_id}/skills/apply", response_model=list[RunSkillApplicationRead])
def apply_run_skills(run_id: str, db: Session = Depends(get_db)) -> list[dict]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    applications = SkillApplicationService().apply_to_run(db, run)
    db.commit()
    return applications


@router.get("/{run_id}/handoff", response_model=HandoffRead)
def get_run_handoff(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    handoff = build_handoff(db, run)
    paths = StorageLayout().for_workspace(run.workspace_id)
    paths.write_json(paths.handoffs / "current.json", handoff)
    return handoff


@router.get("/{run_id}/attack-chains", response_model=list[AttackChainRead])
def get_attack_chains(run_id: str, db: Session = Depends(get_db)) -> list[dict]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return list_attack_chains(db, run_id)


@router.post("/{run_id}/attack-chains", response_model=AttackChainRead)
def create_attack_chain(run_id: str, payload: AttackChainCreate, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    fact = create_attack_chain_fact(db, run_id, payload.model_dump())
    execution_manager.events.emit(
        db,
        run_id,
        "attack_chain",
        f"Attack chain modelled: {fact.value}",
        payload={"attack_chain_id": fact.id, "status": (fact.metadata_json or {}).get("status", "identified")},
    )
    db.commit()
    db.refresh(fact)
    return attack_chain_from_fact(fact)


@router.get("/{run_id}/planning-bundle", response_model=PlanningBundleRead)
def get_planning_bundle(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return build_planning_bundle(db, run)


@router.get("/{run_id}/replay", response_model=ReplayStateRead)
def get_run_replay(run_id: str, limit: int = 400, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    limit = max(10, min(int(limit), 2000))
    state = RunPhaseService().snapshot(run)
    events = (
        db.query(RunEvent)
        .filter(RunEvent.run_id == run_id)
        .order_by(RunEvent.sequence.asc())
        .limit(limit)
        .all()
    )
    artifacts = (
        db.query(Artifact)
        .filter(Artifact.run_id == run_id, Artifact.kind.in_(["report", "report-json"]))
        .order_by(Artifact.created_at.asc())
        .all()
    )
    report_path = next((row.path for row in artifacts if row.kind == "report"), "")
    report_json_path = next((row.path for row in artifacts if row.kind == "report-json"), "")
    manifest = build_replay_manifest(run, events, artifacts, phase_history=list(state.get("history") or []), limit=limit)
    summary = {
        "event_count": len(events),
        "phase_transition_count": len([event for event in events if normalize_event_payload(event.event_type, event.message, event.payload_json)[0] == "phase_transition"]),
        "approval_count": len(
            [
                event
                for event in events
                if normalize_event_payload(event.event_type, event.message, event.payload_json)[0]
                in {"approval_requested", "approval_resolved"}
            ]
        ),
    }
    return {
        "run_id": run_id,
        "status": run.status,
        "phase_history": list(state.get("history") or []),
        "events": [_serialize_event(event) for event in events],
        "report_path": report_path,
        "report_json_path": report_json_path,
        "summary": summary,
        "manifest": manifest,
    }


@router.get("/{run_id}/stream")
def stream_run(run_id: str, db: Session = Depends(get_db)):
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    def event_generator():
        with Session(bind=db.bind) as init_db:
            latest = (
                init_db.query(RunEvent.sequence)
                .filter(RunEvent.run_id == run_id)
                .order_by(RunEvent.sequence.desc())
                .first()
            )
            last_sequence = int(latest[0]) if latest else 0
        while True:
            with Session(bind=db.bind) as stream_db:
                events = (
                    stream_db.query(RunEvent)
                    .filter(RunEvent.run_id == run_id, RunEvent.sequence > last_sequence)
                    .order_by(RunEvent.sequence.asc())
                    .all()
                )
                for event in events:
                    last_sequence = event.sequence
                    payload = _serialize_event(event)
                    payload["payload"] = payload.pop("payload_json", {})
                    payload["created_at"] = event.created_at.isoformat()
                    yield f"data: {json.dumps(payload)}\n\n"
                current_run = stream_db.get(WorkspaceRun, run_id)
                if current_run is None or current_run.status in {"completed", "failed", "cancelled"}:
                    break
            time.sleep(settings.default_stream_poll_interval)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/{run_id}/bus", response_model=list[BusEventRead])
def list_run_bus_events(
    run_id: str,
    branch_id: str = Query("main"),
    after_seq: int = Query(0, ge=0),
    type: str | None = Query(None, description="filter by message type: plan|action|observation|critique|policy_decision"),
    agent: str | None = Query(None, description="filter by agent role"),
    limit: int = Query(200, ge=1, le=2000),
    db: Session = Depends(get_db),
) -> list[BusEvent]:
    if db.get(WorkspaceRun, run_id) is None:
        raise HTTPException(status_code=404, detail="Run not found")
    stmt = (
        db.query(BusEvent)
        .filter(BusEvent.run_id == run_id)
        .filter(BusEvent.branch_id == branch_id)
        .filter(BusEvent.seq > after_seq)
    )
    if type:
        stmt = stmt.filter(BusEvent.type == type)
    if agent:
        stmt = stmt.filter(BusEvent.agent == agent)
    return stmt.order_by(BusEvent.seq.asc()).limit(limit).all()


@router.get("/{run_id}/decision-graph")
def get_decision_graph(
    run_id: str,
    branch_id: str = Query("main"),
    fact_ids: str | None = Query(None, description="comma-separated fact ids to filter the DAG"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """V2-20 — DAG of bus events (nodes=turns, edges=causality)."""
    from secops.services.decision_graph import build_decision_graph

    if db.get(WorkspaceRun, run_id) is None:
        raise HTTPException(status_code=404, detail="Run not found")
    ids = [s for s in (fact_ids.split(",") if fact_ids else []) if s.strip()]
    graph = build_decision_graph(db, run_id, branch_id=branch_id, fact_ids=ids or None)
    return graph.as_dict()
