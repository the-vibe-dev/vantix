from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import subprocess
import time
from urllib.parse import urlparse

from sqlalchemy import select

from secops.config import settings
from secops.db import SessionLocal
from secops.models import (
    Action,
    AgentSession,
    ApprovalRequest,
    Artifact,
    Fact,
    OperatorNote,
    RunMessage,
    Task,
    WorkspaceRun,
)
from secops.mode_profiles import get_mode_profile
from secops.services.codex_runner import CodexRunner
from secops.services.context_builder import ContextBuilder
from secops.services.cve_search import CVESearchService
from secops.services.events import RunEventService
from secops.services.learning import LearningService
from secops.services.memory_writer import DenseMemoryRecord, MemoryWriteService
from secops.services.policies import ExecutionPolicyService
from secops.services.reporting import ReportingService
from secops.services.source_intake import SourceIntakeService
from secops.services.storage import StorageLayout
from secops.services.worker_runtime import worker_runtime
from secops.services.workflows.engine import WorkflowEngine

ROLE_DISPLAY_NAMES = {
    "orchestrator": "Orchestrator",
    "recon": "Vantix Recon",
    "knowledge_base": "Knowledge Base",
    "vector_store": "Vector Store",
    "researcher": "Researcher",
    "developer": "Developer",
    "executor": "Executor",
    "reporter": "Vantix Report",
}


class PhaseBlockedError(Exception):
    pass


class ExecutionManager:
    def __init__(self) -> None:
        self.events = RunEventService()
        self.nas = StorageLayout()
        self.learning = LearningService()
        self.cve = CVESearchService()
        self.memory = MemoryWriteService()
        self.policies = ExecutionPolicyService()
        self.reporting = ReportingService()
        self.source_intake = SourceIntakeService()
        self.workflow_engine = WorkflowEngine()
        self.worker_runtime = worker_runtime

    def start(self, run_id: str) -> str:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None:
                return "Run not found"
            self.workflow_engine.enqueue_run(db, run)
            self.events.emit(db, run.id, "run_status", "Run queued", payload={"status": "queued"})
            self._write_memory(db, run, mode="startup", phase="run-queued", done=["run queued"], next_action="worker claim")
            db.commit()
        self.worker_runtime.ensure_running(self)
        return "Run queued"

    def pause(self, run_id: str) -> str:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None:
                return "Run not found"
            self.workflow_engine.block_run(db, run, "paused-by-operator")
            self.events.emit(db, run.id, "run_status", "Run paused by operator", payload={"status": run.status}, level="warning")
            self._create_approval(
                db,
                run.id,
                title="Run paused",
                detail="Operator requested pause. Add a note and use retry/replan/resume.",
                reason="operator-pause",
            )
            self._write_memory(db, run, mode="handoff", phase="pause", issues=["operator pause"], next_action="add operator note, then retry or replan")
            db.commit()
        return "Pause requested"

    def cancel(self, run_id: str) -> str:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None:
                return "Run not found"
            self.workflow_engine.cancel_run(db, run, reason="cancelled-by-operator")
            self.events.emit(db, run.id, "run_status", "Run cancelled", payload={"status": run.status}, level="warning")
            self._write_memory(db, run, mode="handoff", phase="cancel", issues=["run cancelled"], next_action="review latest events before resuming")
            db.commit()
        return "Cancel requested"

    def execute_phase(self, run_id: str, phase_name: str) -> dict:
        handlers = {
            "context-bootstrap": self._phase_context,
            "source-intake": self._phase_source_intake,
            "source-analysis": self._phase_source_analysis,
            "learning-recall": self._phase_learning,
            "recon-sidecar": self._phase_recon,
            "cve-analysis": self._phase_cve,
            "orchestrate": self._phase_orchestrate,
            "learn-ingest": self._phase_learn_ingest,
            "report": self._phase_report,
        }
        handler = handlers.get(phase_name)
        if handler is None:
            raise ValueError(f"Unknown phase: {phase_name}")
        handler(run_id)
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None:
                raise ValueError(f"Run not found: {run_id}")
            if run.status == "blocked":
                raise PhaseBlockedError(f"Run blocked during phase {phase_name}")
            if run.status == "failed":
                raise RuntimeError(f"Run failed during phase {phase_name}")
        return {"phase": phase_name, "status": "completed"}

    def _check_controls(self, db, run: WorkspaceRun) -> bool:
        return run.status not in {"blocked", "cancelled", "failed"}

    def _phase_context(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "context-bootstrap")
            if task.status == "completed":
                return
            paths = self.nas.for_workspace(run.workspace_id)
            paths.write_json(
                paths.root / "manifest.json",
                {
                    "run_id": run.id,
                    "workspace_id": run.workspace_id,
                    "mode": run.mode,
                    "target": run.target,
                    "objective": run.objective,
                    "config": run.config_json,
                },
            )
            profile = get_mode_profile(run.mode)
            bundle = ContextBuilder().build(
                profile,
                target=run.target,
                ports=run.config_json.get("ports", []),
                services=run.config_json.get("services", []),
                extra_tags=run.config_json.get("tags", []),
            )
            paths.write_text(paths.prompts / "orchestrator_context.txt", bundle["assembled_prompt"])
            self.events.emit(db, run.id, "phase", "Context assembled", payload={"phase": "context-bootstrap"})
            self._write_memory(db, run, mode="phase", phase="context-bootstrap", done=["context assembled"], files=[str(paths.prompts / "orchestrator_context.txt")], next_action="learning recall")
            task.status = "completed"
            task.result_json = {"prompt_path": str(paths.prompts / "orchestrator_context.txt")}
            self._set_vantix_task_status(db, run.id, "flow-initialization", "completed", {"source_phase": "context-bootstrap"})
            db.add(
                Artifact(
                    run_id=run.id,
                    kind="prompt",
                    path=str(paths.prompts / "orchestrator_context.txt"),
                    metadata_json={"mode": run.mode, "profile": profile.id},
                )
            )
            db.commit()

    def _phase_learning(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "learning-recall")
            if task.status == "completed":
                return
            self._set_role_status(db, run.id, "knowledge_base", "running")
            paths = self.nas.for_workspace(run.workspace_id)
            results = self.learning.retrieve_for_run(
                mode=run.mode,
                query=run.objective or run.target or run.mode,
                services=run.config_json.get("services", []),
                ports=run.config_json.get("ports", []),
                tags=run.config_json.get("tags", []),
                limit=25,
            )
            paths.write_json(paths.facts / "learning_hits.json", results)
            task.status = "completed"
            task.result_json = {"hits": len(results)}
            self._set_vantix_task_status(db, run.id, "knowledge-load", "completed", {"hits": len(results), "source_phase": "learning-recall"})
            self.events.emit(db, run.id, "phase", f"Learning recall completed: {len(results)} hits")
            self._set_role_status(db, run.id, "knowledge_base", "completed")
            self._write_memory(db, run, mode="phase", phase="learning-recall", done=[f"learning hits={len(results)}"], files=[str(paths.facts / "learning_hits.json")], next_action="recon sidecar")
            db.commit()

    def _phase_source_intake(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "source-intake")
            if task.status == "completed":
                return
            paths = self.nas.for_workspace(run.workspace_id)
            source_input = dict((run.config_json or {}).get("source_input") or {})
            try:
                context = self.source_intake.resolve_for_run(
                    workspace_root=paths.root,
                    source_input=source_input,
                )
            except Exception as exc:  # noqa: BLE001
                task.status = "failed"
                task.result_json = {"error": str(exc), "source_input": source_input}
                run.status = "failed"
                self.events.emit(db, run.id, "phase", f"Source intake failed: {exc}", level="error")
                db.commit()
                return
            cfg = dict(run.config_json or {})
            cfg["source_input"] = source_input
            cfg["source_context"] = context
            run.config_json = cfg
            task.status = "completed"
            task.result_json = context
            self.events.emit(db, run.id, "phase", f"Source intake {context.get('status', 'completed')}", payload=context)
            self._write_memory(
                db,
                run,
                mode="phase",
                phase="source-intake",
                done=[f"source intake {context.get('status', 'completed')}"],
                next_action="source analysis" if context.get("status") != "skipped" else "learning recall",
            )
            db.commit()

    def _phase_source_analysis(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "source-analysis")
            if task.status == "completed":
                return
            paths = self.nas.for_workspace(run.workspace_id)
            source_ctx = dict((run.config_json or {}).get("source_context") or {})
            resolved = str(source_ctx.get("resolved_path", "")).strip()
            if not resolved or source_ctx.get("status") == "skipped":
                task.status = "completed"
                task.result_json = {"status": "skipped", "reason": "no-source"}
                self.events.emit(db, run.id, "phase", "Source analysis skipped")
                db.commit()
                return

            script_path = settings.repo_root / "scripts" / "source-audit.sh"
            if not script_path.exists():
                task.status = "failed"
                task.result_json = {"error": f"missing script: {script_path}"}
                run.status = "failed"
                db.commit()
                return

            session = self._create_agent_session(db, run.id, "developer", "Source Analyzer", paths)
            self._set_role_status(db, run.id, "developer", "running")
            env = dict(os.environ)
            env["CTF_ROOT"] = str(settings.repo_root)
            env["ARTIFACTS_ROOT"] = str(paths.artifacts)
            command = ["bash", str(script_path), "-d", resolved, "--session", run.id]
            if run.target:
                command += ["-t", run.target]
            self.events.emit(db, run.id, "terminal", f"[source-analysis] starting: {' '.join(command)}", payload={"agent": "developer"}, agent_session_id=session.id)
            started = datetime.now(timezone.utc)
            result = subprocess.run(command, capture_output=True, text=True, env=env)
            output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            self._emit_terminal_excerpt(db, run_id=run.id, output=output, agent_session_id=session.id, agent="developer")

            report_path = ""
            for line in reversed((result.stdout or "").splitlines()):
                if line.strip().lower().startswith("report:"):
                    report_path = line.split(":", 1)[1].strip()
                    break
            if not report_path:
                candidates = sorted(paths.artifacts.rglob("*_findings.md"))
                if candidates:
                    report_path = str(candidates[-1])

            task.result_json = {
                "returncode": result.returncode,
                "report_path": report_path,
                "started_at": started.isoformat(),
            }
            if report_path:
                db.add(Artifact(run_id=run.id, kind="source-audit-report", path=report_path, metadata_json={"source_context": source_ctx}))
            if result.returncode != 0:
                task.status = "failed"
                run.status = "failed"
                self._set_role_status(db, run.id, "developer", "failed")
                self.events.emit(db, run.id, "phase", f"Source analysis failed rc={result.returncode}", level="error")
                db.commit()
                return
            task.status = "completed"
            self._set_role_status(db, run.id, "developer", "completed")
            self.events.emit(db, run.id, "phase", "Source analysis completed", payload={"report_path": report_path})
            self._write_memory(
                db,
                run,
                mode="phase",
                phase="source-analysis",
                done=["source analysis completed"],
                files=[report_path] if report_path else [],
                next_action="learning recall",
            )
            db.commit()

    def _phase_recon(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "recon-sidecar")
            if task.status == "completed":
                return
            paths = self.nas.for_workspace(run.workspace_id)
            session = self._create_agent_session(db, run.id, "recon", "Recon Sidecar", paths)
            self._set_role_status(db, run.id, "recon", "running")
            command = []
            recon_target = self._recon_target(run.target)
            if recon_target:
                if run.config_json.get("ports"):
                    ports = ",".join(run.config_json["ports"])
                    command = ["nmap", "-Pn", "-sT", "-p", ports, "--open", recon_target]
                else:
                    command = ["nmap", "-Pn", "-sT", "--top-ports", "100", "--open", recon_target]
            action_kind = "script" if run.config_json.get("ports") else "recon_high_noise"
            decision = self.policies.evaluate(run, action_kind=action_kind)
            self._emit_policy_decision(
                db,
                run_id=run.id,
                action_kind=action_kind,
                verdict=decision.verdict,
                reason=decision.reason,
                audit=decision.audit,
            )
            if decision.verdict in {"block", "require_approval"}:
                task.status = "blocked"
                task.result_json = {"reason": decision.reason, "verdict": decision.verdict, "action_kind": action_kind}
                run.status = "blocked"
                session.status = "blocked"
                session.completed_at = datetime.now(timezone.utc)
                self._set_role_status(db, run.id, "recon", "blocked")
                self.events.emit(
                    db,
                    run.id,
                    "terminal",
                    f"[recon] blocked by policy: {decision.reason}",
                    level="warning",
                    payload={"agent": "recon", "action_kind": action_kind},
                    agent_session_id=session.id,
                )
                self._create_approval(
                    db,
                    run.id,
                    title="Recon policy blocked run",
                    detail=decision.reason,
                    reason=f"{action_kind}-policy",
                )
                self.events.emit(db, run.id, "phase", f"Recon blocked by policy: {decision.reason}", level="warning", agent_session_id=session.id)
                self._write_memory(
                    db,
                    run,
                    mode="handoff",
                    phase="recon-blocked",
                    issues=[decision.reason],
                    files=[str(session.log_path)],
                    next_action="review approval and retry",
                )
                db.commit()
                return
            self.events.emit(
                db,
                run.id,
                "terminal",
                f"[recon] starting: {' '.join(command) if command else 'no command'}",
                payload={"agent": "recon"},
                agent_session_id=session.id,
            )
            output = self._run_command(command, session.log_path, run_id=run.id) if command else "No target supplied; recon skipped.\n"
            paths.write_text(Path(session.log_path), output)
            self._emit_terminal_excerpt(db, run_id=run.id, output=output, agent_session_id=session.id, agent="recon")
            discovered = self._parse_nmap(output)
            if discovered["ports"]:
                run.config_json["ports"] = sorted(set(run.config_json.get("ports", []) + discovered["ports"]))
            if discovered["services"]:
                run.config_json["services"] = sorted(set(run.config_json.get("services", []) + discovered["services"]))
            for port in discovered["ports"]:
                db.add(Fact(run_id=run.id, source="recon", kind="port", value=port, confidence=0.95, tags=["recon"]))
            for service in discovered["services"]:
                db.add(Fact(run_id=run.id, source="recon", kind="service", value=service, confidence=0.95, tags=["recon"]))
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            self._set_role_status(db, run.id, "recon", "completed")
            task.status = "completed"
            task.result_json = discovered
            self._set_vantix_task_status(db, run.id, "vantix-recon", "completed", {"source_phase": "recon-sidecar", **discovered})
            self.events.emit(db, run.id, "phase", "Recon completed", payload=discovered, agent_session_id=session.id)
            facts = [[ "port", port ] for port in discovered["ports"]] + [[ "service", service ] for service in discovered["services"]]
            self._write_memory(db, run, mode="phase", phase="recon", done=["recon completed"], facts=facts, files=[str(session.log_path)], next_action="cve analysis")
            if str(run.config_json.get("scan_profile", "full")).lower() == "quick":
                cfg = dict(run.config_json or {})
                cfg["quick_scan_recon_done"] = True
                cfg["quick_scan_gate_pending"] = True
                run.config_json = cfg
                self.events.emit(
                    db,
                    run.id,
                    "phase",
                    "Quick scan recon complete",
                    level="warning",
                    agent_session_id=session.id,
                )
            db.add(
                Artifact(
                    run_id=run.id,
                    kind="recon-log",
                    path=str(session.log_path),
                    metadata_json={"ports": discovered["ports"], "services": discovered["services"]},
                )
            )
            db.commit()

    def _phase_cve(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "cve-analysis")
            if task.status == "completed":
                return
            if bool((run.config_json or {}).get("quick_scan_gate_pending")):
                run.status = "blocked"
                self.events.emit(
                    db,
                    run.id,
                    "terminal",
                    "[cve] waiting for operator approval to continue beyond quick scan",
                    level="warning",
                    payload={"agent": "researcher"},
                )
                self._create_approval(
                    db,
                    run.id,
                    title="Recon complete: continue beyond quick scan",
                    detail="Recon completed successfully. Approve to continue with CVE analysis, orchestration, and reporting phases.",
                    reason="quick-scan-gate",
                )
                db.commit()
                return
            paths = self.nas.for_workspace(run.workspace_id)
            session = self._create_agent_session(db, run.id, "researcher", "Researcher Sidecar", paths)
            self._set_role_status(db, run.id, "researcher", "running")
            results = []
            errors = []
            services = run.config_json.get("services", [])
            for service in services:
                try:
                    response = self.cve.search(vendor=service, product=service, always_search_external=True, live_limit=500)
                except Exception as exc:  # noqa: BLE001
                    response = {"source": "cve-search", "query": service, "results": [], "error": str(exc)}
                    errors.append({"service": service, "error": str(exc)})
                    self.events.emit(
                        db,
                        run.id,
                        "phase",
                        f"CVE lookup failed for {service}: {exc}",
                        level="warning",
                        agent_session_id=session.id,
                    )
                results.append(response)
                for top in response.get("results", [])[:5]:
                    db.add(
                        Fact(
                            run_id=run.id,
                            source="cve-search",
                            kind="cve",
                            value=top.get("id", ""),
                            confidence=float(top.get("cvss", 0) or 0),
                            tags=[service, "cve"],
                            metadata_json=top,
                        )
                    )
            cve_path = paths.facts / "cve_results.json"
            paths.write_json(cve_path, results)
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            self._set_role_status(db, run.id, "researcher", "completed")
            self._set_role_status(db, run.id, "vector_store", "completed")
            task.status = "completed"
            task.result_json = {"queries": len(results), "errors": errors}
            self._set_vantix_task_status(db, run.id, "research", "completed", {"queries": len(results), "errors": len(errors), "source_phase": "cve-analysis"})
            self._set_vantix_task_status(db, run.id, "vector-store", "completed", {"queries": len(results), "source_phase": "cve-analysis"})
            self.events.emit(db, run.id, "phase", f"CVE analysis completed: {len(results)} queries", agent_session_id=session.id)
            self._write_memory(db, run, mode="phase", phase="cve-analysis", done=[f"cve queries={len(results)}"], files=[str(cve_path)], next_action="primary orchestration")
            db.add(Artifact(run_id=run.id, kind="cve-results", path=str(cve_path), metadata_json={"queries": len(results)}))
            db.commit()

    def _phase_orchestrate(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "orchestrate")
            if task.status == "completed":
                return
            paths = self.nas.for_workspace(run.workspace_id)
            session = self._create_agent_session(db, run.id, "orchestrator", "Primary Orchestrator", paths)
            notes = db.execute(select(OperatorNote).where(OperatorNote.run_id == run.id).order_by(OperatorNote.created_at.asc())).scalars().all()
            note_block = "\n".join(f"- {note.content}" for note in notes) if notes else "(none)"
            facts = db.execute(select(Fact).where(Fact.run_id == run.id).order_by(Fact.created_at.asc())).scalars().all()
            fact_block = "\n".join(f"- [{fact.kind}] {fact.value}" for fact in facts[:50]) or "(none)"
            learning_block = self._learning_block(paths)
            prompt_path = paths.prompts / "live_orchestrator_prompt.txt"
            prompt = (paths.prompts / "orchestrator_context.txt").read_text(encoding="utf-8", errors="ignore")
            prompt += f"\n\n[Run Facts]\n{fact_block}\n"
            if learning_block:
                prompt += f"\n[Targeted Learning]\n{learning_block}\n"
            prompt += f"\n[Operator Notes]\n{note_block}\n"
            paths.write_text(prompt_path, prompt)
            session.prompt_path = str(prompt_path)
            session.status = "running"
            self._set_role_status(db, run.id, "orchestrator", "running")
            self._set_role_status(db, run.id, "developer", "running")
            self._set_role_status(db, run.id, "executor", "running")
            db.flush()
            self.events.emit(db, run.id, "phase", "Primary orchestration started", agent_session_id=session.id)
            self._write_memory(db, run, mode="phase", phase="orchestrate-start", done=["primary orchestration started"], files=[str(prompt_path)], next_action="monitor orchestrator")
            db.commit()

            log_path = Path(session.log_path)
            codex_policy = self.policies.evaluate(run, action_kind="codex")
            with SessionLocal() as inner_db:
                self._emit_policy_decision(
                    inner_db,
                    run_id=run.id,
                    action_kind="codex",
                    verdict=codex_policy.verdict,
                    reason=codex_policy.reason,
                    audit=codex_policy.audit,
                )
                inner_db.commit()
            if codex_policy.verdict in {"block", "require_approval"}:
                simulated = (
                    f"Codex execution policy verdict: {codex_policy.verdict}.\n"
                    f"Reason: {codex_policy.reason}\n"
                    "Review policy status, then retry/replan.\n"
                )
                paths.write_text(log_path, simulated)
                with SessionLocal() as inner_db:
                    inner_run = inner_db.get(WorkspaceRun, run.id)
                    if inner_run is not None:
                        inner_run.status = "blocked"
                    refreshed = inner_db.get(AgentSession, session.id)
                    refreshed.status = "blocked"
                    refreshed.completed_at = datetime.now(timezone.utc)
                    self._set_role_status(inner_db, run.id, "orchestrator", "blocked")
                    task = self._task_by_kind(inner_db, run.id, "orchestrate")
                    task.status = "blocked"
                    task.result_json = {"reason": codex_policy.reason, "verdict": codex_policy.verdict}
                    self.events.emit(inner_db, run.id, "terminal", simulated.strip(), level="warning", agent_session_id=session.id)
                    self._write_memory(inner_db, inner_db.get(WorkspaceRun, run.id), mode="handoff", phase="orchestrate-blocked", issues=[codex_policy.reason], files=[str(log_path)], next_action="review approval/policy and retry")
                    self._create_approval(
                        inner_db,
                        run.id,
                        title="Codex execution policy blocked run",
                        detail=codex_policy.reason,
                        reason="codex-policy",
                    )
                    inner_db.commit()
                return
            if settings.enable_codex_execution:
                runner = CodexRunner(workspace_dir=Path(session.workspace_path))
                if not runner.is_available():
                    message = f"Codex binary not found: {settings.codex_bin}\n"
                    paths.write_text(log_path, message)
                    with SessionLocal() as inner_db:
                        inner_run = inner_db.get(WorkspaceRun, run.id)
                        if inner_run is not None:
                            inner_run.status = "blocked"
                        refreshed = inner_db.get(AgentSession, session.id)
                        refreshed.status = "blocked"
                        refreshed.completed_at = datetime.now(timezone.utc)
                        self._set_role_status(inner_db, run.id, "orchestrator", "blocked")
                        task = self._task_by_kind(inner_db, run.id, "orchestrate")
                        task.status = "blocked"
                        task.result_json = {"reason": "codex-unavailable", "codex_bin": settings.codex_bin}
                        self.events.emit(
                            inner_db,
                            run.id,
                            "terminal",
                            message.strip(),
                            level="warning",
                            agent_session_id=session.id,
                        )
                        self._create_approval(
                            inner_db,
                            run.id,
                            title="Codex binary unavailable",
                            detail=message.strip(),
                            reason="codex-unavailable",
                        )
                        inner_db.add(
                            Artifact(
                                run_id=run.id,
                                kind="terminal-log",
                                path=str(log_path),
                                metadata_json={"agent_session_id": session.id},
                            )
                        )
                        inner_db.commit()
                    return
                plan = runner.build_plan(prompt)
                with log_path.open("w", encoding="utf-8") as handle:
                    def on_line(line: str) -> None:
                        handle.write(line)
                        handle.flush()
                        with SessionLocal() as inner_db:
                            self.events.emit(
                                inner_db,
                                run.id,
                                "terminal",
                                line.rstrip("\n"),
                                payload={"agent": "orchestrator"},
                                agent_session_id=session.id,
                            )
                            inner_db.commit()

                    result = runner.execute_streaming(plan, on_line=on_line, stop_event=None)
                with SessionLocal() as inner_db:
                    inner_run = inner_db.get(WorkspaceRun, run.id)
                    if inner_run is not None and result.returncode != 0:
                        inner_run.status = "failed"
                    refreshed = inner_db.get(AgentSession, session.id)
                    refreshed.status = "completed" if result.returncode == 0 else "failed"
                    refreshed.completed_at = datetime.now(timezone.utc)
                    self._set_role_status(inner_db, run.id, "orchestrator", "completed" if result.returncode == 0 else "failed")
                    self._set_role_status(inner_db, run.id, "developer", "completed" if result.returncode == 0 else "failed")
                    self._set_role_status(inner_db, run.id, "executor", "completed" if result.returncode == 0 else "failed")
                    task = self._task_by_kind(inner_db, run.id, "orchestrate")
                    task.status = "completed" if result.returncode == 0 else "failed"
                    task.result_json = {"returncode": result.returncode}
                    if result.returncode == 0:
                        self._set_vantix_task_status(inner_db, run.id, "planning", "completed", {"source_phase": "orchestrate"})
                        self._set_vantix_task_status(inner_db, run.id, "development", "completed", {"source_phase": "orchestrate"})
                        self._set_vantix_task_status(inner_db, run.id, "execution", "completed", {"source_phase": "orchestrate"})
                    self._write_memory(
                        inner_db,
                        inner_db.get(WorkspaceRun, run.id),
                        mode="phase" if result.returncode == 0 else "failure",
                        phase="orchestrate",
                        done=[f"orchestrator returncode={result.returncode}"],
                        issues=[] if result.returncode == 0 else [f"orchestrator failed rc={result.returncode}"],
                        files=[str(log_path)],
                        next_action="learning ingest" if result.returncode == 0 else "review terminal log and retry or replan",
                    )
                    if result.returncode != 0:
                        self._create_approval(
                            inner_db,
                            run.id,
                            title="Codex orchestration failed",
                            detail=f"Return code {result.returncode}. Review terminal output and retry or replan.",
                            reason="codex-failure",
                        )
                    inner_db.add(Artifact(run_id=run.id, kind="terminal-log", path=str(log_path), metadata_json={"agent_session_id": session.id}))
                    inner_db.commit()

    def _phase_learn_ingest(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or run.status in {"blocked", "cancelled", "failed"}:
                return
            task = self._task_by_kind(db, run.id, "learn-ingest")
            if task.status == "completed":
                return
            paths = self.nas.for_workspace(run.workspace_id)
            ingest_output = self.learning.ingest_path(paths.root)
            paths.write_text(paths.logs / "learn_ingest.log", ingest_output)
            task.status = "completed"
            task.result_json = {"output": ingest_output.strip()}
            self.events.emit(db, run.id, "phase", "Learning ingest completed")
            self._write_memory(db, run, mode="phase", phase="learn-ingest", done=["learning ingest completed"], files=[str(paths.logs / "learn_ingest.log")], next_action="generate report")
            db.add(Artifact(run_id=run.id, kind="learning-log", path=str(paths.logs / "learn_ingest.log"), metadata_json={}))
            db.commit()

    def _recon_target(self, target: str) -> str:
        if not target:
            return ""
        parsed = urlparse(target)
        if parsed.scheme and parsed.hostname:
            return parsed.hostname
        return target

    def _learning_block(self, paths: StorageLayout) -> str:
        learning_path = paths.facts / "learning_hits.json"
        if not learning_path.exists():
            return ""
        try:
            rows = json.loads(learning_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return ""
        lines = []
        for row in rows[:5]:
            title = str(row.get("title", "")).strip()
            summary = str(row.get("summary_short") or row.get("summary") or "").strip()
            rank = row.get("rank", "")
            if not title:
                continue
            line = f"- {title}"
            if rank != "":
                line += f" (rank {rank})"
            if summary:
                line += f": {summary}"
            lines.append(line)
        return "\n".join(lines)

    def _phase_report(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or run.status in {"blocked", "cancelled", "failed"}:
                return
            task = self._task_by_kind(db, run.id, "report")
            if task.status == "completed":
                return
            self._set_role_status(db, run.id, "reporter", "running")
            generated = self.reporting.generate(db, run)
            task.status = "completed"
            self._set_role_status(db, run.id, "reporter", "completed")
            self._set_vantix_task_status(db, run.id, "reporting", "completed", {"source_phase": "report"})
            task.result_json = {"report_path": generated["markdown_path"], "report_json_path": generated["json_path"]}
            db.add(
                Artifact(
                    run_id=run.id,
                    kind="report",
                    path=str(generated["markdown_path"]),
                    metadata_json={"report_json_path": generated["json_path"]},
                )
            )
            db.add(Artifact(run_id=run.id, kind="report-json", path=str(generated["json_path"]), metadata_json={}))
            self.events.emit(db, run.id, "phase", "Report generated")
            self._write_memory(db, run, mode="phase", phase="report", done=["report generated"], files=[str(generated["markdown_path"]), str(generated["json_path"])], next_action="close run")
            db.commit()

    def _task_by_kind(self, db, run_id: str, kind: str) -> Task:
        return db.execute(select(Task).where(Task.run_id == run_id, Task.kind == kind)).scalar_one()

    def _set_vantix_task_status(self, db, run_id: str, kind: str, status: str, result: dict | None = None) -> None:
        row = (
            db.query(Task)
            .filter(Task.run_id == run_id, Task.kind == kind)
            .order_by(Task.created_at.desc())
            .first()
        )
        if row is None:
            return
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

    def _emit_terminal_excerpt(
        self,
        db,
        *,
        run_id: str,
        output: str,
        agent_session_id: str,
        agent: str,
        max_lines: int = 120,
    ) -> None:
        lines = [line for line in output.splitlines() if line.strip()]
        if not lines:
            self.events.emit(
                db,
                run_id,
                "terminal",
                f"[{agent}] no output",
                payload={"agent": agent},
                agent_session_id=agent_session_id,
            )
            return
        for line in lines[:max_lines]:
            self.events.emit(
                db,
                run_id,
                "terminal",
                line,
                payload={"agent": agent},
                agent_session_id=agent_session_id,
            )
        if len(lines) > max_lines:
            self.events.emit(
                db,
                run_id,
                "terminal",
                f"[{agent}] output truncated ({len(lines) - max_lines} lines omitted)",
                payload={"agent": agent},
                agent_session_id=agent_session_id,
            )

    def _create_approval(self, db, run_id: str, title: str, detail: str, reason: str) -> ApprovalRequest:
        existing = (
            db.query(ApprovalRequest)
            .filter(
                ApprovalRequest.run_id == run_id,
                ApprovalRequest.reason == reason,
                ApprovalRequest.status == "pending",
            )
            .order_by(ApprovalRequest.created_at.desc())
            .first()
        )
        if existing is not None:
            return existing
        approval = ApprovalRequest(run_id=run_id, title=title, detail=detail, reason=reason, status="pending")
        db.add(approval)
        self.events.emit(db, run_id, "approval", title, level="warning", payload={"reason": reason})
        db.add(
            RunMessage(
                run_id=run_id,
                role="system",
                author="System",
                content=f"Approval required: {title}. {detail}",
                metadata_json={"approval_reason": reason},
            )
        )
        return approval

    def _write_memory(
        self,
        db,
        run: WorkspaceRun | None,
        *,
        mode: str,
        phase: str,
        done: list[str] | None = None,
        issues: list[str] | None = None,
        files: list[str] | None = None,
        facts: list[list[str]] | None = None,
        next_action: str = "",
    ) -> None:
        if run is None:
            return
        try:
            self.memory.write(
                DenseMemoryRecord(
                    mode=mode,
                    run_id=run.id,
                    phase=phase,
                    objective=run.objective,
                    done=done or [],
                    issues=issues or [],
                    files=files or [],
                    facts=facts or [],
                    next_action=next_action,
                    context=[run.mode, *run.config_json.get("tags", [])],
                ),
                db=db,
            )
        except Exception as exc:  # noqa: BLE001
            self.events.emit(db, run.id, "memory_error", f"Memory write failed: {exc}", level="warning")

    def _run_command(self, command: list[str], log_path: str, *, run_id: str | None = None) -> str:
        if not command:
            return ""
        if run_id is not None:
            with SessionLocal() as db:
                run = db.get(WorkspaceRun, run_id)
                if run is None:
                    return "Run not found for command execution.\n"
                decision = self.policies.evaluate(run, action_kind="script")
        else:
            decision = None
        if decision is not None:
            if decision.verdict in {"block", "require_approval"}:
                return f"Command blocked by policy: {decision.reason}\n"
        started = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        timed_out = False
        cancelled = False
        try:
            while True:
                try:
                    stdout, stderr = process.communicate(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    if run_id:
                        with SessionLocal() as db:
                            run = db.get(WorkspaceRun, run_id)
                            if run is None or run.status in {"cancelled", "failed"}:
                                cancelled = True
                                process.terminate()
                                try:
                                    stdout, stderr = process.communicate(timeout=3)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                    stdout, stderr = process.communicate()
                                break
                    if time.monotonic() - started > 120:
                        timed_out = True
                        process.terminate()
                        try:
                            stdout, stderr = process.communicate(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            stdout, stderr = process.communicate()
                        break
            elapsed = max(0.0, time.monotonic() - started)
            output = self.policies._redact(stdout or "", redactions=[settings.secret_key])  # noqa: SLF001
            err = self.policies._redact(stderr or "", redactions=[settings.secret_key])  # noqa: SLF001
            combined = output + ("\n" + err if err else "")
            if cancelled:
                return combined + "\nCommand interrupted: run cancelled.\n"
            if timed_out:
                return combined + f"\nCommand timed out after {elapsed:.1f}s.\n"
            if process.returncode != 0:
                return combined + f"\nCommand failed rc={process.returncode} after {elapsed:.1f}s.\n"
            return combined
        except OSError as exc:
            return f"Command failed (oserror): {exc}\n"

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
        agent.status = status
        if status in {"completed", "failed", "blocked"}:
            agent.completed_at = datetime.now(timezone.utc)

    def _emit_policy_decision(
        self,
        db,
        *,
        run_id: str,
        action_kind: str,
        verdict: str,
        reason: str,
        audit: bool,
    ) -> None:
        self.events.emit(
            db,
            run_id,
            "policy_decision",
            f"policy:{action_kind}:{verdict}",
            level="warning" if verdict in {"block", "require_approval"} else "info",
            payload={"action_kind": action_kind, "verdict": verdict, "reason": reason, "audit": audit},
        )

    def _parse_nmap(self, output: str) -> dict[str, list[str]]:
        ports = re.findall(r"(?m)^(\d{1,5})/tcp\s+open", output)
        services = re.findall(r"(?m)^\d{1,5}/tcp\s+open\s+([a-zA-Z0-9_.-]+)", output)
        return {"ports": sorted(set(ports)), "services": sorted(set(services))}


execution_manager = ExecutionManager()
