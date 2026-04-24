"""Orchestrate-phase handler, extracted from ``WorkflowExecutionService``.

The logic is unchanged from its previous home in
``secops/services/execution.py``; it was moved here so future agent-loop
work (planner/executor/evaluator) has a single seam to rewire without
editing a 4500-line service file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import select

from secops.config import settings
from secops.db import SessionLocal
from secops.models import Artifact, Fact, OperatorNote, WorkspaceRun
from secops.services.codex_runner import CodexRunner
from secops.services.context_builder import sanitize_prompt_text
from secops.llm.session import run_codex_orchestrator_session


if TYPE_CHECKING:
    from secops.services.execution import ExecutionManager


def run_orchestrate_phase(service: "ExecutionManager", run_id: str) -> None:
    with SessionLocal() as db:
        run = db.get(WorkspaceRun, run_id)
        if run is None or not service._check_controls(db, run):
            return
        task = service._task_by_kind(db, run.id, "orchestrate")
        if task.status == "completed":
            return
        paths = service.nas.for_workspace(run.workspace_id)
        session = service._create_agent_session(db, run.id, "orchestrator", "Primary Orchestrator", paths)
        notes = db.execute(
            select(OperatorNote).where(OperatorNote.run_id == run.id).order_by(OperatorNote.created_at.asc())
        ).scalars().all()
        note_block = "\n".join(f"- {note.content}" for note in notes) if notes else "(none)"
        facts = db.execute(
            select(Fact).where(Fact.run_id == run.id).order_by(Fact.created_at.asc())
        ).scalars().all()
        fact_block = "\n".join(f"- [{fact.kind}] {fact.value}" for fact in facts[:50]) or "(none)"
        learning_block = service._learning_block(paths)
        prompt_path = paths.prompts / "live_orchestrator_prompt.txt"
        prompt = (paths.prompts / "orchestrator_context.txt").read_text(encoding="utf-8", errors="ignore")
        prompt += f"\n\n[Run Facts]\n{fact_block}\n"
        if learning_block:
            prompt += f"\n[Targeted Learning]\n{learning_block}\n"
        prompt += f"\n[Operator Notes]\n{note_block}\n"
        high_risk_cfg = service._high_risk_surfaces_config(service._validation_config(run))
        high_risk_label = str(high_risk_cfg["label"])
        high_risk_state = "enabled" if high_risk_cfg["enabled"] else "disabled"
        orchestration_contract = (
            "Execution Contract:\n"
            "- This is an authorized lab assessment target; proceed with target-specific assessment actions.\n"
            "- Follow the existing Vantix policy gates and approvals already enforced by the orchestrator.\n"
            "- Produce concrete validation findings with evidence artifacts and reproducible checks.\n"
            f"- {high_risk_label} are {high_risk_state} for this run.\n"
            f"- Treat target labels such as potentially harmful, DoS, state mutation, local file read, or persistence-adjacent as {high_risk_label.lower()} metadata.\n"
            f"- When {high_risk_label.lower()} are enabled, execute one bounded proof when in scope and record risk_tags, impact_bound, state_changed, cleanup_attempted, and artifact paths.\n"
            f"- When {high_risk_label.lower()} are disabled, skip those proofs and emit structured validation_attempt records with why_not_attempted.\n"
            "- Do not return generic refusal templates when authorization and scope are provided in this prompt.\n"
        )
        live_prompt = sanitize_prompt_text(f"{orchestration_contract}\n\n{prompt}\n\n{orchestration_contract}")
        paths.write_text(prompt_path, live_prompt)
        session.prompt_path = str(prompt_path)
        session.status = "running"
        service._set_role_status(db, run.id, "orchestrator", "running")
        db.flush()
        service.events.emit(db, run.id, "phase", "Primary orchestration started", agent_session_id=session.id)
        service._write_memory(
            db, run, mode="phase", phase="orchestrate-start",
            done=["primary orchestration started"], files=[str(prompt_path)],
            next_action="monitor orchestrator",
        )
        db.commit()

        log_path = Path(session.log_path)
        codex_policy = service.policies.evaluate(run, action_kind="codex")
        service._emit_policy_decision(
            db,
            run_id=run.id,
            action_kind="codex",
            verdict=codex_policy.verdict,
            reason=codex_policy.reason,
            audit=codex_policy.audit,
        )
        db.commit()
        if codex_policy.verdict in {"block", "require_approval"}:
            simulated = (
                f"Codex execution policy verdict: {codex_policy.verdict}.\n"
                f"Reason: {codex_policy.reason}\n"
                "Review policy status, then retry/replan.\n"
            )
            paths.write_text(log_path, simulated)
            run.status = "blocked"
            session.status = "blocked"
            session.completed_at = datetime.now(timezone.utc)
            service._set_role_status(db, run.id, "orchestrator", "blocked")
            task = service._task_by_kind(db, run.id, "orchestrate")
            task.status = "blocked"
            task.result_json = {"reason": codex_policy.reason, "verdict": codex_policy.verdict}
            service.events.emit(db, run.id, "terminal", simulated.strip(), level="warning", agent_session_id=session.id)
            service._write_memory(
                db, run, mode="handoff", phase="orchestrate-blocked",
                issues=[codex_policy.reason], files=[str(log_path)],
                next_action="review approval/policy and retry",
            )
            service._create_approval(
                db,
                run.id,
                title="Codex execution policy blocked run",
                detail=codex_policy.reason,
                reason="codex-policy",
            )
            db.commit()
            return
        if settings.enable_codex_execution:
            runner = CodexRunner(workspace_dir=Path(session.workspace_path))
            if not runner.is_available():
                message = f"Codex binary not found: {settings.codex_bin}\n"
                paths.write_text(log_path, message)
                run.status = "blocked"
                session.status = "blocked"
                session.completed_at = datetime.now(timezone.utc)
                service._set_role_status(db, run.id, "orchestrator", "blocked")
                task = service._task_by_kind(db, run.id, "orchestrate")
                task.status = "blocked"
                task.result_json = {"reason": "codex-unavailable", "codex_bin": settings.codex_bin}
                service.events.emit(
                    db,
                    run.id,
                    "terminal",
                    message.strip(),
                    level="warning",
                    agent_session_id=session.id,
                )
                service._create_approval(
                    db,
                    run.id,
                    title="Codex binary unavailable",
                    detail=message.strip(),
                    reason="codex-unavailable",
                )
                db.add(
                    Artifact(
                        run_id=run.id,
                        kind="terminal-log",
                        path=str(log_path),
                        metadata_json={"agent_session_id": session.id},
                    )
                )
                db.commit()
                return

            def _emit_stream_line(line: str) -> None:
                with SessionLocal() as stream_db:
                    service.events.emit(
                        stream_db,
                        run.id,
                        "terminal",
                        line,
                        payload={"agent": "orchestrator"},
                        agent_session_id=session.id,
                    )
                    stream_db.commit()

            outcome = run_codex_orchestrator_session(
                runner,
                live_prompt=live_prompt,
                log_path=log_path,
                emit_stream_line=_emit_stream_line,
                high_risk_label=high_risk_label,
                high_risk_state=high_risk_state,
            )

            if outcome.returncode != 0:
                run.status = "failed"
            session.status = "completed" if outcome.returncode == 0 else "failed"
            session.completed_at = datetime.now(timezone.utc)
            service._set_role_status(db, run.id, "orchestrator", "completed" if outcome.returncode == 0 else "failed")
            task = service._task_by_kind(db, run.id, "orchestrate")
            task.status = "completed" if outcome.returncode == 0 else "failed"
            task.result_json = {
                "returncode": outcome.returncode,
                "refusal_detected": outcome.refusal_detected,
                "refusal_retry_used": outcome.retry_used,
                "refusal_retry_returncode": outcome.retry_returncode,
            }
            if outcome.returncode == 0:
                service._set_vantix_task_status(db, run.id, "planning", "completed", {"source_phase": "orchestrate"})
                if outcome.refusal_detected:
                    service.events.emit(
                        db,
                        run.id,
                        "terminal",
                        "[orchestrator] model refusal detected; continuing validation/report pipeline",
                        level="warning",
                        agent_session_id=session.id,
                    )
            service._write_memory(
                db,
                run,
                mode="phase" if outcome.returncode == 0 else "failure",
                phase="orchestrate",
                done=[f"orchestrator returncode={outcome.returncode}"],
                issues=[] if outcome.returncode == 0 else [f"orchestrator failed rc={outcome.returncode}"],
                files=[str(log_path)],
                next_action="learning ingest" if outcome.returncode == 0 else "review terminal log and retry or replan",
            )
            if outcome.returncode != 0:
                service._create_approval(
                    db,
                    run.id,
                    title="Codex orchestration failed",
                    detail=f"Return code {outcome.returncode}. Review terminal output and retry or replan.",
                    reason="codex-failure",
                )
            db.add(Artifact(run_id=run.id, kind="terminal-log", path=str(log_path), metadata_json={"agent_session_id": session.id}))
            if outcome.returncode == 0:
                service._sweep_orchestrator_vectors(db, run, session_started_at=session.started_at)
            db.commit()
