from __future__ import annotations

import json
import time

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from secops.config import settings
from secops.db import get_db
from secops.models import AgentSession, ApprovalRequest, Artifact, Fact, Finding, OperatorNote, ProviderConfig, RunEvent, RunMessage, Task, WorkspaceRun
from secops.mode_profiles import get_mode_profile
from secops.schemas import (
    AgentSessionRead,
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
    RunGraphRead,
    RunLearningRead,
    RunRead,
    RunEventRead,
    RunMessageRead,
    TaskRead,
    TerminalRead,
    ArtifactRead,
    VectorCreate,
    VectorRead,
    RunResultsRead,
    RunSkillApplicationRead,
    RunPhaseRead,
    FindingPromotionCreate,
    FindingRead,
    RunProviderRouteCreate,
)
from secops.security import require_api_token
from secops.services.context_builder import ContextBuilder
from secops.services.execution import execution_manager
from secops.services.finding_promotion import FindingPromotionService
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
from secops.services.vantix import create_vector_fact, summarize_terminal, vector_from_fact, VantixScheduler


router = APIRouter(prefix="/api/v1/runs", tags=["runs"], dependencies=[Depends(require_api_token)])


@router.post("", response_model=RunRead)
def create_run(payload: RunCreate, db: Session = Depends(get_db)) -> WorkspaceRun:
    service = RunService(db)
    try:
        run = service.create_run(
            engagement_id=payload.engagement_id,
            objective=payload.objective,
            target=payload.target,
            ports=payload.ports,
            services=payload.services,
            tags=payload.tags,
            config=payload.config,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return run


@router.get("", response_model=list[RunRead])
def list_runs(db: Session = Depends(get_db)) -> list[WorkspaceRun]:
    return db.query(WorkspaceRun).order_by(WorkspaceRun.started_at.desc()).all()


@router.get("/{run_id}", response_model=RunRead)
def get_run(run_id: str, db: Session = Depends(get_db)) -> WorkspaceRun:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


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
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    run.status = "queued"
    db.commit()
    message = execution_manager.start(run_id)
    return RunControlResponse(run_id=run_id, status=run.status, message=message)


@router.post("/{run_id}/replan", response_model=RunControlResponse)
def replan_run(run_id: str, db: Session = Depends(get_db)) -> RunControlResponse:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    run.status = "queued"
    db.commit()
    message = execution_manager.start(run_id)
    return RunControlResponse(run_id=run_id, status=run.status, message=f"Replan requested. {message}")


@router.get("/{run_id}/graph", response_model=RunGraphRead)
def get_run_graph(run_id: str, db: Session = Depends(get_db)) -> RunGraphRead:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
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


@router.get("/{run_id}/facts", response_model=list[FactRead])
def list_run_facts(run_id: str, db: Session = Depends(get_db)) -> list[Fact]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(Fact).filter(Fact.run_id == run_id).order_by(Fact.created_at.asc()).all()


@router.get("/{run_id}/events", response_model=list[RunEventRead])
def list_run_events(run_id: str, db: Session = Depends(get_db)) -> list[RunEvent]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(RunEvent).filter(RunEvent.run_id == run_id).order_by(RunEvent.sequence.asc()).all()


@router.get("/{run_id}/terminal", response_model=TerminalRead)
def get_run_terminal(run_id: str, db: Session = Depends(get_db)) -> TerminalRead:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    events = db.query(RunEvent).filter(RunEvent.run_id == run_id, RunEvent.event_type == "terminal").order_by(RunEvent.sequence.asc()).all()
    content = "\n".join(event.message for event in events)
    return TerminalRead(run_id=run_id, content=content)


@router.get("/{run_id}/approvals", response_model=list[ApprovalRead])
def list_run_approvals(run_id: str, db: Session = Depends(get_db)) -> list[ApprovalRequest]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(ApprovalRequest).filter(ApprovalRequest.run_id == run_id).order_by(ApprovalRequest.created_at.asc()).all()


@router.post("/{run_id}/operator-notes", response_model=OperatorNoteRead)
def create_operator_note(run_id: str, payload: OperatorNoteCreate, db: Session = Depends(get_db)) -> OperatorNote:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    note = OperatorNote(run_id=run_id, content=payload.content, author=payload.author, applies_to=payload.applies_to)
    db.add(note)
    db.commit()
    db.refresh(note)
    paths = StorageLayout().for_workspace(run.workspace_id)
    note_path = paths.notes / f"{note.created_at.strftime('%Y%m%d_%H%M%S')}_{note.id}.md"
    note_path.write_text(
        f"# Operator Note\n\n- Author: {note.author}\n- Applies To: {note.applies_to}\n- Content: {note.content}\n",
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
def list_run_messages(run_id: str, db: Session = Depends(get_db)) -> list[RunMessage]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return db.query(RunMessage).filter(RunMessage.run_id == run_id).order_by(RunMessage.created_at.asc()).all()


@router.get("/{run_id}/vectors", response_model=list[VectorRead])
def list_run_vectors(run_id: str, db: Session = Depends(get_db)) -> list[dict]:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    facts = db.query(Fact).filter(Fact.run_id == run_id, Fact.kind == "vector").order_by(Fact.confidence.desc(), Fact.created_at.asc()).all()
    return [vector_from_fact(fact) for fact in facts]


@router.get("/{run_id}/phase", response_model=RunPhaseRead)
def get_run_phase(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    phase = RunPhaseService().refresh(db, run, reason="phase-read")
    db.commit()
    return phase


@router.post("/{run_id}/vectors", response_model=VectorRead)
def create_run_vector(run_id: str, payload: VectorCreate, db: Session = Depends(get_db)) -> dict:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    fact = create_vector_fact(db, run_id, payload.model_dump())
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
    return {
        "run_id": run.id,
        "status": run.status,
        "findings": findings,
        "artifacts": artifacts,
        "vectors": vectors,
        "terminal_summary": summarize_terminal(events),
        "report_path": report,
    }


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
    db.commit()
    db.refresh(fact)
    return attack_chain_from_fact(fact)


@router.get("/{run_id}/stream")
def stream_run(run_id: str, db: Session = Depends(get_db)):
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    def event_generator():
        last_sequence = 0
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
                    payload = {
                        "id": event.id,
                        "sequence": event.sequence,
                        "event_type": event.event_type,
                        "level": event.level,
                        "message": event.message,
                        "payload": event.payload_json,
                        "created_at": event.created_at.isoformat(),
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                current_run = stream_db.get(WorkspaceRun, run_id)
                if current_run is None or current_run.status in {"blocked", "completed", "failed", "cancelled"}:
                    break
            time.sleep(settings.default_stream_poll_interval)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
