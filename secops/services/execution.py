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
from secops.services.browser_runtime import BrowserRuntimeService
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
    "browser": "Browser Analyst",
    "knowledge_base": "Knowledge Base",
    "vector_store": "Vector Store",
    "researcher": "Researcher",
    "developer": "Developer",
    "executor": "Executor",
    "reporter": "Vantix Report",
}

TASK_METADATA = {
    "context-bootstrap": ("Context Bootstrap", "Assemble workflow context, prompts, and normalized run state."),
    "source-intake": ("Source Intake", "Resolve source input for white-box analysis."),
    "source-analysis": ("Source Analysis", "Run source-level analysis and extract findings."),
    "learning-recall": ("Knowledge Recall", "Load dense memory, learning hits, tool guidance, and prior cases."),
    "recon-sidecar": ("Vantix Recon", "Collect low-noise service, port, and target facts."),
    "browser-assessment": ("Browser Assessment", "Explore in-scope web application behavior and capture evidence."),
    "cve-analysis": ("Vulnerability Research", "Query CVE, exploit, and vulnerability intelligence."),
    "orchestrate": ("Orchestrator Planning", "Select next action and branch between validation, execution, or report."),
    "learn-ingest": ("Execution Review", "Ingest execution evidence and learning artifacts."),
    "report": ("Vantix Report", "Summarize evidence, findings, and operator-ready report output."),
    "flow-initialization": ("Orchestrator", "Normalize target, objective, scope, and run state."),
    "vantix-recon": ("Vantix Recon", "Collect low-noise service, port, and target facts."),
    "knowledge-load": ("Knowledge Base", "Load dense memory, learning hits, tool guidance, and prior cases."),
    "vector-store": ("Vector Store", "Rank similar cases and candidate attack patterns."),
    "research": ("Researcher", "Query CVE, exploit, and vulnerability intelligence."),
    "planning": ("Orchestrator Planning", "Select next action and branch between recon, development, execution, or report."),
    "development": ("Developer", "Prepare validation helpers, payload notes, or exploit implementation guidance."),
    "execution": ("Executor", "Run the selected vector through current execution controls."),
    "reporting": ("Vantix Report", "Summarize evidence, artifacts, validated findings, and next steps."),
}


class PhaseBlockedError(Exception):
    pass


class ExecutionManager:
    def __init__(self) -> None:
        self.events = RunEventService()
        self.nas = StorageLayout()
        self.learning = LearningService()
        self.cve = CVESearchService()
        self.browser = BrowserRuntimeService()
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
            "browser-assessment": self._phase_browser,
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
            cfg = dict(run.config_json or {})
            recon_target = self._recon_target(run.target)
            if recon_target:
                scope_verdict = self._enforce_scope(db, run, recon_target)
                if not scope_verdict.allowed:
                    task.status = "blocked"
                    task.result_json = {"reason": scope_verdict.reason, "verdict": "out_of_scope", "target": recon_target}
                    run.status = "blocked"
                    session.status = "blocked"
                    session.completed_at = datetime.now(timezone.utc)
                    self._set_role_status(db, run.id, "recon", "blocked")
                    self.events.emit(
                        db,
                        run.id,
                        "terminal",
                        f"[recon] blocked: target {recon_target} out of engagement scope — {scope_verdict.reason}",
                        level="warning",
                        payload={"agent": "recon", "action_kind": "scope", "target": recon_target},
                        agent_session_id=session.id,
                    )
                    self._create_approval(
                        db,
                        run.id,
                        title="Target out of scope",
                        detail=f"{recon_target}: {scope_verdict.reason}",
                        reason="scope-policy",
                        metadata={"target": recon_target},
                    )
                    self._write_memory(
                        db,
                        run,
                        mode="handoff",
                        phase="recon-blocked",
                        issues=[f"scope: {scope_verdict.reason}"],
                        next_action="update engagement scope allowlist",
                    )
                    db.commit()
                    return
                if cfg.get("ports"):
                    ports = ",".join(cfg["ports"])
                    command = ["nmap", "-Pn", "-sT", "-p", ports, "--open", recon_target]
                else:
                    top_ports = "50" if str(cfg.get("scan_profile", "full")).lower() == "quick" else "100"
                    command = ["nmap", "-Pn", "-sT", "--top-ports", top_ports, "--open", recon_target]
            action_kind = "recon_high_noise"
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
                    metadata={"target": recon_target, "action_kind": action_kind},
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
            if self._should_escalate_recon(run, discovered):
                escalate = ["nmap", "-Pn", "-sT", "--top-ports", "1000", "--open", recon_target]
                self.events.emit(
                    db,
                    run.id,
                    "terminal",
                    f"[recon] escalating: {' '.join(escalate)}",
                    payload={"agent": "recon", "pass": 2},
                    agent_session_id=session.id,
                )
                output2 = self._run_command(escalate, session.log_path, run_id=run.id)
                combined = output.rstrip() + "\n\n# pass-2 top1000\n" + output2
                paths.write_text(Path(session.log_path), combined)
                self._emit_terminal_excerpt(db, run_id=run.id, output=output2, agent_session_id=session.id, agent="recon")
                merged = self._parse_nmap(combined)
                discovered = merged
                cfg["recon_escalated"] = True
                run.config_json = cfg
            if discovered["ports"]:
                cfg["ports"] = sorted(set(cfg.get("ports", []) + discovered["ports"]))
            if discovered["services"]:
                cfg["services"] = sorted(set(cfg.get("services", []) + discovered["services"]))
            run.config_json = cfg
            web_summary = self._web_followup_checks(
                db=db,
                run=run,
                recon_target=recon_target,
                discovered=discovered,
                session_id=session.id,
                paths=paths,
            )
            for port in discovered["ports"]:
                db.add(Fact(run_id=run.id, source="recon", kind="port", value=port, confidence=0.95, tags=["recon"]))
            for service in discovered["services"]:
                db.add(Fact(run_id=run.id, source="recon", kind="service", value=service, confidence=0.95, tags=["recon"]))
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            self._set_role_status(db, run.id, "recon", "completed")
            task.status = "completed"
            task.result_json = {**discovered, "web_followup": web_summary}
            self._set_vantix_task_status(db, run.id, "vantix-recon", "completed", {"source_phase": "recon-sidecar", **discovered})
            self.events.emit(db, run.id, "phase", "Recon completed", payload=discovered, agent_session_id=session.id)
            db.add(
                RunMessage(
                    run_id=run.id,
                    role="system",
                    author="System",
                    content=f"Recon completed: {len(discovered['ports'])} open ports, {len(discovered['services'])} detected services.",
                    metadata_json={"phase": "recon", "ports": discovered["ports"], "services": discovered["services"]},
                )
            )
            if web_summary.get("hits", 0) > 0:
                db.add(
                    RunMessage(
                        run_id=run.id,
                        role="system",
                        author="System",
                        content=f"Web validation flagged {web_summary['hits']} candidate issue(s) across {web_summary['checked_ports']} port(s).",
                        metadata_json={"phase": "recon", "web_followup": web_summary},
                    )
                )
            facts = [[ "port", port ] for port in discovered["ports"]] + [[ "service", service ] for service in discovered["services"]]
            self._write_memory(db, run, mode="phase", phase="recon", done=["recon completed"], facts=facts, files=[str(session.log_path)], next_action="cve analysis")
            if str(cfg.get("scan_profile", "full")).lower() == "quick":
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
            cve_hits = 0
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
                live_meta = dict(response.get("live") or {})
                live_attempted = bool(live_meta.get("attempted"))
                live_upserted = int(live_meta.get("upserted", 0) or 0)
                live_errors = [str(item) for item in (live_meta.get("errors") or [])]
                live_sources = [str(item) for item in (live_meta.get("sources") or [])]
                db.add(
                    Fact(
                        run_id=run.id,
                        source="cve-search",
                        kind="intel",
                        value=f"{service}: live attempted={live_attempted} upserted={live_upserted}",
                        confidence=0.8 if live_upserted > 0 else 0.6,
                        tags=["intel", "cve", service],
                        metadata_json={
                            "service": service,
                            "live_attempted": live_attempted,
                            "live_upserted": live_upserted,
                            "live_sources": live_sources,
                            "live_errors": live_errors,
                            "result_count": len(response.get("results") or []),
                        },
                    )
                )
                db.add(
                    RunMessage(
                        run_id=run.id,
                        role="system",
                        author="System",
                        content=(
                            f"CVE search `{service}`: {len(response.get('results') or [])} local result(s); "
                            f"external attempted={live_attempted}, upserted={live_upserted}, errors={len(live_errors)}."
                        ),
                        metadata_json={
                            "phase": "cve-analysis",
                            "service": service,
                            "live": live_meta,
                        },
                    )
                )
                cve_hits += len(response.get("results", []) or [])
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
            task.result_json = {"queries": len(results), "errors": errors, "hits": cve_hits}
            self._set_vantix_task_status(db, run.id, "research", "completed", {"queries": len(results), "errors": len(errors), "source_phase": "cve-analysis"})
            self._set_vantix_task_status(db, run.id, "vector-store", "completed", {"queries": len(results), "source_phase": "cve-analysis"})
            self.events.emit(db, run.id, "phase", f"CVE analysis completed: {len(results)} queries", agent_session_id=session.id)
            db.add(
                RunMessage(
                    run_id=run.id,
                    role="system",
                    author="System",
                    content=f"CVE search completed: {len(results)} service queries, {cve_hits} matches, {len(errors)} errors.",
                    metadata_json={"phase": "cve-analysis", "queries": len(results), "hits": cve_hits, "errors": len(errors)},
                )
            )
            self._write_memory(db, run, mode="phase", phase="cve-analysis", done=[f"cve queries={len(results)}"], files=[str(cve_path)], next_action="primary orchestration")
            db.add(Artifact(run_id=run.id, kind="cve-results", path=str(cve_path), metadata_json={"queries": len(results)}))
            db.commit()

    def _phase_browser(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "browser-assessment")
            if task.status == "completed":
                return
            paths = self.nas.for_workspace(run.workspace_id)
            session = self._create_agent_session(db, run.id, "browser", "Browser Analyst", paths)
            session.status = "running"
            self._set_role_status(db, run.id, "browser", "running")
            target_url = str(((run.config_json or {}).get("browser") or {}).get("entry_url") or run.target or "").strip()
            action_kind = "browser_assessment"
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
                self._set_role_status(db, run.id, "browser", "blocked")
                self.events.emit(
                    db,
                    run.id,
                    "terminal",
                    f"[browser] blocked by policy: {decision.reason}",
                    level="warning",
                    payload={"agent": "browser", "action_kind": action_kind},
                    agent_session_id=session.id,
                )
                self._create_approval(
                    db,
                    run.id,
                    title="Browser assessment policy blocked run",
                    detail=decision.reason,
                    reason=f"{action_kind}-policy",
                    metadata={"target": target_url},
                )
                self._write_memory(
                    db,
                    run,
                    mode="handoff",
                    phase="browser-blocked",
                    issues=[decision.reason],
                    files=[str(paths.logs / "browser.log")],
                    next_action="review approval and retry",
                )
                db.commit()
                return

            browser_cfg = dict((run.config_json or {}).get("browser") or {})
            if browser_cfg.get("allow_auth") and (run.config_json or {}).get("browser_auth"):
                auth_decision = self.policies.evaluate(run, action_kind="browser_auth")
                self._emit_policy_decision(
                    db,
                    run_id=run.id,
                    action_kind="browser_auth",
                    verdict=auth_decision.verdict,
                    reason=auth_decision.reason,
                    audit=auth_decision.audit,
                )
                if auth_decision.verdict in {"block", "require_approval"}:
                    task.status = "blocked"
                    task.result_json = {"reason": auth_decision.reason, "verdict": auth_decision.verdict, "action_kind": "browser_auth"}
                    run.status = "blocked"
                    session.status = "blocked"
                    session.completed_at = datetime.now(timezone.utc)
                    self._set_role_status(db, run.id, "browser", "blocked")
                    self._create_approval(
                        db,
                        run.id,
                        title="Browser auth session requires approval",
                        detail=auth_decision.reason,
                        reason="browser_auth-policy",
                        metadata={"target": target_url},
                    )
                    db.commit()
                    return

            self.events.emit(
                db,
                run.id,
                "terminal",
                f"[browser] starting assessment: {target_url or '(none)'}",
                payload={"agent": "browser"},
                agent_session_id=session.id,
            )
            result = self.browser.assess(
                run_id=run.id,
                workspace_root=paths.root,
                target=target_url,
                run_config=dict(run.config_json or {}),
            )
            for item in result.artifacts:
                kind = str(item.get("kind") or "")
                path = str(item.get("path") or "")
                if not kind or not path:
                    continue
                db.add(
                    Artifact(
                        run_id=run.id,
                        kind=kind,
                        path=path,
                        metadata_json={
                            "phase": "browser-assessment",
                            "agent_session_id": session.id,
                            "captured_at": result.completed_at,
                        },
                    )
                )
            route_values: list[str] = []
            emitted_vectors: set[str] = set()
            for obs in result.observations:
                route_values.append(obs.url)
                db.add(
                    Fact(
                        run_id=run.id,
                        source="browser-runtime",
                        kind="route",
                        value=obs.url,
                        confidence=0.9,
                        tags=["browser", "route"],
                        metadata_json={
                            "title": obs.title,
                            "depth": obs.depth,
                            "dom_summary": obs.dom_summary,
                            "route_hints": obs.route_hints[:10],
                            "js_signal_kinds": [str(item.get("kind") or "") for item in obs.js_signals[:10]],
                        },
                    )
                )
                if obs.forms:
                    db.add(
                        Fact(
                            run_id=run.id,
                            source="browser-runtime",
                            kind="form",
                            value=obs.url,
                            confidence=0.82,
                            tags=["browser", "form"],
                            metadata_json={"forms": obs.forms[:20], "title": obs.title},
                        )
                    )
                    if any(bool(form.get("auth_like")) for form in obs.forms):
                        title = f"Auth boundary candidate at {obs.url}"
                        if title not in emitted_vectors:
                            emitted_vectors.add(title)
                            vector = self._browser_vector(
                                run_id=run.id,
                                title=title,
                                summary="Authentication-like form discovered; validate route guards and session transitions.",
                                severity="medium",
                                evidence=f"Route {obs.url} exposes auth-like form fields.",
                                tags=["browser", "auth-boundary"],
                                prerequisites=["authenticated session context"],
                                noise_level="quiet",
                                requires_approval=True,
                            )
                            db.add(vector)
                if obs.storage_summary:
                    db.add(
                        Fact(
                            run_id=run.id,
                            source="browser-runtime",
                            kind="browser-session",
                            value=obs.url,
                            confidence=0.7,
                            tags=["browser", "session"],
                            metadata_json=obs.storage_summary,
                        )
                    )
                    if int(obs.storage_summary.get("local_storage_keys") or 0) > 0 or int(obs.storage_summary.get("session_storage_keys") or 0) > 0:
                        title = f"Client-side session trust boundary candidate at {obs.url}"
                        if title not in emitted_vectors:
                            emitted_vectors.add(title)
                            db.add(
                                self._browser_vector(
                                    run_id=run.id,
                                    title=title,
                                    summary="Client storage or session state is present; validate trust boundaries and authorization coupling.",
                                    severity="medium",
                                    evidence=f"Observed local/session storage state on {obs.url}: {obs.storage_summary}",
                                    tags=["browser", "session-boundary"],
                                    prerequisites=["session validation"],
                                    noise_level="quiet",
                                    requires_approval=True,
                                )
                            )
                privileged_hints = [item for item in (obs.route_hints or []) if any(token in item.lower() for token in ("/admin", "/debug", "/manage", "/internal"))]
                if privileged_hints or any("admin" in link.lower() or "debug" in link.lower() for link in obs.links):
                    title = f"Hidden/admin surface candidate at {obs.url}"
                    if title not in emitted_vectors:
                        emitted_vectors.add(title)
                        vector = self._browser_vector(
                            run_id=run.id,
                            title=title,
                            summary="Discovered route links or inline route hints suggest privileged or debug surface exposure.",
                            severity="high",
                            evidence=f"Observed privileged route hints from {obs.url}: {(privileged_hints or obs.links)[:6]}",
                            tags=["browser", "admin-surface"],
                            prerequisites=["route validation"],
                            noise_level="quiet",
                            requires_approval=True,
                        )
                        db.add(vector)
                for hint in (obs.route_hints or [])[:20]:
                    db.add(
                        Fact(
                            run_id=run.id,
                            source="browser-runtime",
                            kind="browser-route-hint",
                            value=hint,
                            confidence=0.7,
                            tags=["browser", "route-hint"],
                            metadata_json={"page": obs.url, "title": obs.title},
                        )
                    )
                for signal in (obs.js_signals or [])[:20]:
                    signal_kind = str(signal.get("kind") or "unknown")
                    signal_text = str(signal.get("signal") or "").strip()
                    if not signal_text:
                        continue
                    db.add(
                        Fact(
                            run_id=run.id,
                            source="browser-runtime",
                            kind="js-signal",
                            value=f"{signal_kind}: {signal_text[:180]}",
                            confidence=0.68,
                            tags=["browser", "js-signal", signal_kind],
                            metadata_json={"page": obs.url, "kind": signal_kind, "signal": signal_text[:180]},
                        )
                    )
                    if signal_kind in {"app-config", "debug-signal"}:
                        title = f"Client trust boundary candidate at {obs.url}"
                        if title not in emitted_vectors:
                            emitted_vectors.add(title)
                            db.add(
                                self._browser_vector(
                                    run_id=run.id,
                                    title=title,
                                    summary="Client-side configuration or debug signal may expose internal trust assumptions or sensitive behavior.",
                                    severity="medium",
                                    evidence=f"Observed {signal_kind} signal on {obs.url}: {signal_text[:180]}",
                                    tags=["browser", "client-trust"],
                                    prerequisites=["configuration review", "bounded validation"],
                                    noise_level="quiet",
                                    requires_approval=True,
                                )
                            )

            if result.auth_transitions:
                db.add(
                    Fact(
                        run_id=run.id,
                        source="browser-runtime",
                        kind="browser-auth-transition",
                        value=result.authenticated,
                        confidence=0.8,
                        tags=["browser", "auth-state"],
                        metadata_json={
                            "transitions": result.auth_transitions[:10],
                            "dom_diffs": result.dom_diffs[:10],
                            "session_summary": result.session_summary,
                        },
                    )
                )
                if result.authenticated == "partial":
                    title = "Insecure state transition candidate"
                    if title not in emitted_vectors:
                        emitted_vectors.add(title)
                        db.add(
                            self._browser_vector(
                                run_id=run.id,
                                title=title,
                                summary="Authentication flow produced a partial session state; validate route guards, state transitions, and logout/login boundaries.",
                                severity="medium",
                                evidence=f"Browser auth transitions ended in partial state with {len(result.dom_diffs)} captured deltas.",
                                tags=["browser", "state-transition"],
                                prerequisites=["auth flow review"],
                                noise_level="quiet",
                                requires_approval=True,
                            )
                        )

            for endpoint in result.network_summary.get("endpoints", [])[:80]:
                value = str(endpoint.get("endpoint") or "").strip()
                if not value:
                    continue
                db.add(
                    Fact(
                        run_id=run.id,
                        source="browser-runtime",
                        kind="api-endpoint",
                        value=value,
                        confidence=0.75,
                        tags=["browser", "api"],
                        metadata_json={"count": int(endpoint.get("count") or 0)},
                    )
                )
            if result.network_summary.get("endpoints"):
                title = "Client-side/API mismatch candidate"
                if title not in emitted_vectors:
                    emitted_vectors.add(title)
                    vector = self._browser_vector(
                        run_id=run.id,
                        title=title,
                        summary="Browser-captured endpoints indicate API surface requiring authorization and trust-boundary validation.",
                        severity="medium",
                        evidence=f"Observed {len(result.network_summary.get('endpoints') or [])} API endpoint patterns in browser network capture.",
                        tags=["browser", "api-surface"],
                        prerequisites=["api authorization checks"],
                        noise_level="quiet",
                        requires_approval=True,
                    )
                    db.add(vector)

            if route_values:
                chain_payload = {
                    "name": "Browser recon to validation",
                    "score": min(99.0, 40.0 + float(len(route_values))),
                    "status": "candidate",
                    "steps": [
                        {"phase": "browser-assessment", "action": "route-discovery"},
                        {"phase": "planning", "action": "vector-selection"},
                    ],
                    "mitre_ids": ["T1595"],
                    "notes": f"Browser discovered {len(route_values)} in-scope routes and generated candidate vectors.",
                    "provenance": {"source": "browser-runtime", "route_count": len(route_values), "artifact_kinds": [item.get("kind") for item in result.artifacts]},
                }
                db.add(
                    Fact(
                        run_id=run.id,
                        source="browser-runtime",
                        kind="attack_chain",
                        value=chain_payload["name"],
                        confidence=0.72,
                        tags=["browser", "planning"],
                        metadata_json=chain_payload,
                    )
                )

            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            self._set_role_status(db, run.id, "browser", "completed")
            task.status = "completed"
            task.result_json = {
                "entry_url": result.entry_url,
                "current_url": result.current_url,
                "authenticated": result.authenticated,
                "pages": len(result.observations),
                "routes": len(route_values),
                "network_requests": int(result.network_summary.get("total_requests") or 0),
                "blocked_actions": result.blocked_actions,
                "auth_transitions": len(result.auth_transitions),
                "dom_diffs": len(result.dom_diffs),
            }
            self._set_vantix_task_status(
                db,
                run.id,
                "browser-assessment",
                "completed",
                {"source_phase": "browser-assessment", "pages": len(result.observations), "routes": len(route_values)},
            )
            self.events.emit(
                db,
                run.id,
                "phase",
                f"Browser assessment completed: {len(result.observations)} pages, {len(route_values)} routes",
                payload={
                    "phase": "browser-assessment",
                    "entry_url": result.entry_url,
                    "authenticated": result.authenticated,
                    "blocked_actions": result.blocked_actions,
                },
                agent_session_id=session.id,
            )
            db.add(
                RunMessage(
                    run_id=run.id,
                    role="system",
                    author="System",
                    content=f"Browser assessment: pages={len(result.observations)}, routes={len(route_values)}, authenticated={result.authenticated}.",
                    metadata_json={"phase": "browser-assessment", "routes": len(route_values), "pages": len(result.observations)},
                )
            )
            self._write_memory(
                db,
                run,
                mode="phase",
                phase="browser-assessment",
                done=[f"browser pages={len(result.observations)}", f"routes={len(route_values)}"],
                files=[item["path"] for item in result.artifacts if item.get("path")][:10],
                next_action="cve analysis",
            )
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
            db.flush()
            self.events.emit(db, run.id, "phase", "Primary orchestration started", agent_session_id=session.id)
            self._write_memory(db, run, mode="phase", phase="orchestrate-start", done=["primary orchestration started"], files=[str(prompt_path)], next_action="monitor orchestrator")
            db.commit()

            log_path = Path(session.log_path)
            codex_policy = self.policies.evaluate(run, action_kind="codex")
            self._emit_policy_decision(
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
                self._set_role_status(db, run.id, "orchestrator", "blocked")
                task = self._task_by_kind(db, run.id, "orchestrate")
                task.status = "blocked"
                task.result_json = {"reason": codex_policy.reason, "verdict": codex_policy.verdict}
                self.events.emit(db, run.id, "terminal", simulated.strip(), level="warning", agent_session_id=session.id)
                self._write_memory(db, run, mode="handoff", phase="orchestrate-blocked", issues=[codex_policy.reason], files=[str(log_path)], next_action="review approval/policy and retry")
                self._create_approval(
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
                    self._set_role_status(db, run.id, "orchestrator", "blocked")
                    task = self._task_by_kind(db, run.id, "orchestrate")
                    task.status = "blocked"
                    task.result_json = {"reason": "codex-unavailable", "codex_bin": settings.codex_bin}
                    self.events.emit(
                        db,
                        run.id,
                        "terminal",
                        message.strip(),
                        level="warning",
                        agent_session_id=session.id,
                    )
                    self._create_approval(
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
                plan = runner.build_plan(prompt)
                with log_path.open("w", encoding="utf-8") as handle:
                    def on_line(line: str) -> None:
                        handle.write(line)
                        handle.flush()
                        # Streaming events need their own short-lived session so
                        # they do not collide with the outer unit-of-work.
                        with SessionLocal() as stream_db:
                            self.events.emit(
                                stream_db,
                                run.id,
                                "terminal",
                                line.rstrip("\n"),
                                payload={"agent": "orchestrator"},
                                agent_session_id=session.id,
                            )
                            stream_db.commit()

                    result = runner.execute_streaming(plan, on_line=on_line, stop_event=None)
                if result.returncode != 0:
                    run.status = "failed"
                session.status = "completed" if result.returncode == 0 else "failed"
                session.completed_at = datetime.now(timezone.utc)
                self._set_role_status(db, run.id, "orchestrator", "completed" if result.returncode == 0 else "failed")
                task = self._task_by_kind(db, run.id, "orchestrate")
                task.status = "completed" if result.returncode == 0 else "failed"
                task.result_json = {"returncode": result.returncode}
                if result.returncode == 0:
                    self._set_vantix_task_status(db, run.id, "planning", "completed", {"source_phase": "orchestrate"})
                self._write_memory(
                    db,
                    run,
                    mode="phase" if result.returncode == 0 else "failure",
                    phase="orchestrate",
                    done=[f"orchestrator returncode={result.returncode}"],
                    issues=[] if result.returncode == 0 else [f"orchestrator failed rc={result.returncode}"],
                    files=[str(log_path)],
                    next_action="learning ingest" if result.returncode == 0 else "review terminal log and retry or replan",
                )
                if result.returncode != 0:
                    self._create_approval(
                        db,
                        run.id,
                        title="Codex orchestration failed",
                        detail=f"Return code {result.returncode}. Review terminal output and retry or replan.",
                        reason="codex-failure",
                    )
                db.add(Artifact(run_id=run.id, kind="terminal-log", path=str(log_path), metadata_json={"agent_session_id": session.id}))
                db.commit()

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

    def _enforce_scope(self, db: "Session", run: "WorkspaceRun", target: str) -> "ScopeVerdict":
        """Resolve engagement scope metadata and validate target.

        Returns a ScopeVerdict; callers must block when not allowed.
        A granted ``scope-policy`` approval is consumed as a one-time override.
        """
        from secops.models import Engagement
        from secops.services.scope import ScopeVerdict, is_scope_allowed

        engagement = db.get(Engagement, run.engagement_id) if run.engagement_id else None
        scope = {}
        if engagement is not None and isinstance(engagement.metadata_json, dict):
            raw = engagement.metadata_json.get("scope")
            if isinstance(raw, dict):
                scope = raw
        allowed = scope.get("allowed") or []
        excludes = scope.get("excludes") or []
        allow_private = bool(scope.get("allow_private", False))
        config = dict(run.config_json or {})
        scope_overrides = dict(config.get("scope_overrides") or {})
        if bool(scope_overrides.get(target)):
            allow_private = True
        grants_raw = config.get("approval_grants")
        grants = dict(grants_raw) if isinstance(grants_raw, dict) else {}
        scope_grants = int(grants.get("scope", 0) or 0)
        if scope_grants > 0:
            # Consume exactly one scope override grant approved by operator.
            grants["scope"] = scope_grants - 1
            config["approval_grants"] = grants
            run.config_json = config
            allow_private = True
        # Permit the engagement's own target as an implicit allow-entry.
        if engagement and engagement.target and engagement.target not in allowed:
            allowed = list(allowed) + [engagement.target]
        return is_scope_allowed(target, allowed=allowed, excludes=excludes, allow_private=allow_private)

    def _should_escalate_recon(self, run: WorkspaceRun, discovered: dict[str, list[str]]) -> bool:
        cfg = dict(run.config_json or {})
        if str(cfg.get("scan_profile", "full")).lower() == "quick":
            return False
        if bool(cfg.get("recon_escalated")):
            return False
        if cfg.get("ports"):
            return False
        ports = [int(port) for port in discovered.get("ports", []) if str(port).isdigit()]
        if not ports:
            return True
        high_port_present = any(port >= 10000 for port in ports)
        if len(ports) < 8:
            return True
        return not high_port_present

    def _web_followup_checks(
        self,
        *,
        db,
        run: WorkspaceRun,
        recon_target: str,
        discovered: dict[str, list[str]],
        session_id: str,
        paths: StorageLayout,
    ) -> dict:
        if not recon_target:
            return {"checked_ports": 0, "hits": 0, "checks": 0}
        cfg = dict(run.config_json or {})
        if str(cfg.get("scan_profile", "full")).lower() == "quick":
            return {"checked_ports": 0, "hits": 0, "checks": 0, "skipped": "quick-scan-profile"}
        if bool(cfg.get("web_followup_done")):
            return {"checked_ports": 0, "hits": 0, "checks": 0, "skipped": "already-done"}
        ports = [port for port in discovered.get("ports", []) if str(port).isdigit()]
        if not ports:
            return {"checked_ports": 0, "hits": 0, "checks": 0}

        candidate_ports = []
        for port in ports:
            p = int(port)
            if p in {80, 443, 3000, 5000, 8000, 8080, 8443} or p >= 1024:
                candidate_ports.append(str(p))
        candidate_ports = sorted(set(candidate_ports), key=lambda value: int(value))
        if not candidate_ports:
            return {"checked_ports": 0, "hits": 0, "checks": 0}

        source_paths = ["/server.py", "/app.py", "/main.py", "/.env", "/.git/config"]
        traversal_paths = ["/../../etc/passwd", "/..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd"]
        issues: list[dict[str, str]] = []
        checks = 0
        sample_lines: list[str] = []
        for port in candidate_ports[:10]:
            base_url = f"http://{recon_target}:{port}"
            probe = self._run_command(["curl", "-sS", "-L", "--max-time", "4", base_url + "/"], str(paths.logs / "recon.log"), run_id=run.id)
            checks += 1
            if "HTTP/" not in probe and "<html" not in probe.lower() and "command failed" in probe.lower():
                continue
            for path in source_paths:
                resp = self._run_command(["curl", "-sS", "-L", "--max-time", "4", base_url + path], str(paths.logs / "recon.log"), run_id=run.id)
                checks += 1
                body = resp.lower()
                if "import " in body or "def " in body or "flask" in body or "django" in body:
                    issues.append({"port": port, "kind": "source-disclosure", "path": path, "evidence": f"{base_url}{path}"})
                    sample_lines.append(f"[web] potential source disclosure: {base_url}{path}")
                    break
            for path in traversal_paths:
                resp = self._run_command(
                    ["curl", "-sS", "-L", "--path-as-is", "--max-time", "4", base_url + path],
                    str(paths.logs / "recon.log"),
                    run_id=run.id,
                )
                checks += 1
                text = resp.lower()
                if "root:x:" in text or "/bin/bash" in text:
                    issues.append({"port": port, "kind": "path-traversal-read", "path": path, "evidence": f"{base_url}{path}"})
                    sample_lines.append(f"[web] potential traversal file-read: {base_url}{path}")
                    break

        for issue in issues:
            db.add(
                Fact(
                    run_id=run.id,
                    source="recon-web",
                    kind="vector",
                    value=f"{issue['kind']} on {issue['port']}",
                    confidence=0.85,
                    tags=["web", "candidate"],
                    metadata_json={
                        "title": issue["kind"],
                        "summary": f"Potential {issue['kind']} identified during automated web validation.",
                        "status": "candidate",
                        "severity": "high",
                        "evidence": issue["evidence"],
                        "next_action": "validate safely and capture proof",
                        "port": issue["port"],
                        "path": issue["path"],
                        "source": "recon-web",
                    },
                )
            )
        for line in sample_lines[:20]:
            self.events.emit(
                db,
                run.id,
                "terminal",
                line,
                payload={"agent": "recon", "stage": "web-followup"},
                agent_session_id=session_id,
            )
        cfg["web_followup_done"] = True
        run.config_json = cfg
        if issues:
            report_path = paths.logs / "web-followup.json"
            paths.write_json(report_path, {"target": recon_target, "issues": issues, "checks": checks})
            db.add(Artifact(run_id=run.id, kind="web-followup", path=str(report_path), metadata_json={"hits": len(issues), "checks": checks}))
        return {"checked_ports": len(candidate_ports[:10]), "hits": len(issues), "checks": checks}

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
            self.events.emit(
                db,
                run.id,
                "phase",
                "Report generated",
                payload={
                    "phase": "report",
                    "report_path": generated["markdown_path"],
                    "report_json_path": generated["json_path"],
                },
            )
            db.add(
                RunMessage(
                    run_id=run.id,
                    role="system",
                    author="System",
                    content=f"Report generated: {generated['markdown_path']}",
                    metadata_json={"phase": "report", "report_path": generated["markdown_path"]},
                )
            )
            self._write_memory(db, run, mode="phase", phase="report", done=["report generated"], files=[str(generated["markdown_path"]), str(generated["json_path"])], next_action="close run")
            db.commit()

    def _browser_vector(
        self,
        *,
        run_id: str,
        title: str,
        summary: str,
        severity: str,
        evidence: str,
        tags: list[str],
        prerequisites: list[str],
        noise_level: str,
        requires_approval: bool,
    ) -> Fact:
        score = 0.45
        if severity.lower() in {"high", "critical"}:
            score += 0.2
        if requires_approval:
            score += 0.08
        if noise_level == "quiet":
            score += 0.06
        metadata = {
            "title": title,
            "summary": summary,
            "source": "browser-runtime",
            "severity": severity.lower(),
            "status": "candidate",
            "evidence": evidence,
            "next_action": "review browser evidence and validate safely",
            "noise_level": noise_level,
            "requires_approval": requires_approval,
            "evidence_quality": 0.72,
            "source_credibility": 0.8,
            "novelty": 0.55,
            "noise_level_score": 0.2 if noise_level == "quiet" else 0.7,
            "prerequisites_satisfied": 0.5,
            "prerequisites": prerequisites,
            "score": round(min(0.99, max(0.0, score)), 3),
            "provenance": {"facts": [], "artifacts": [], "origin_phase": "browser-assessment"},
            "scope_check": "required-before-validation",
            "safety_notes": "Bounded validation only; operator approval required for high-risk actions.",
        }
        return Fact(
            run_id=run_id,
            source="browser-runtime",
            kind="vector",
            value=title,
            confidence=float(metadata["score"]),
            tags=tags,
            metadata_json=metadata,
        )

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

    def _create_approval(
        self,
        db,
        run_id: str,
        title: str,
        detail: str,
        reason: str,
        metadata: dict | None = None,
    ) -> ApprovalRequest:
        metadata = metadata or {}
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
        if existing is not None and (not metadata or all(existing.metadata_json.get(key) == value for key, value in metadata.items())):
            return existing
        latest = (
            db.query(ApprovalRequest)
            .filter(ApprovalRequest.run_id == run_id, ApprovalRequest.reason == reason)
            .order_by(ApprovalRequest.created_at.desc())
            .first()
        )
        if latest is not None and latest.status == "approved":
            same_context = not metadata or all((latest.metadata_json or {}).get(key) == value for key, value in metadata.items())
            approved_recently = (datetime.now(timezone.utc) - latest.updated_at).total_seconds() <= 300
            if same_context and approved_recently:
                return latest
        approval = ApprovalRequest(run_id=run_id, title=title, detail=detail, reason=reason, status="pending", metadata_json=metadata)
        db.add(approval)
        self.events.emit(db, run_id, "approval", title, level="warning", payload={"reason": reason, **metadata})
        db.add(
            RunMessage(
                run_id=run_id,
                role="system",
                author="System",
                content=f"Approval required: {title}. {detail}",
                metadata_json={"approval_reason": reason, **metadata},
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
