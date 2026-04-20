from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import subprocess
import time
from urllib import request as urlrequest
from urllib import error as urlerror
from urllib.parse import quote, urlencode, urlparse

from sqlalchemy import select

from secops.config import settings
from secops.db import SessionLocal
from secops.models import (
    Action,
    AgentSession,
    ApprovalRequest,
    Artifact,
    Fact,
    Finding,
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
from secops.services.exploit_validation import ExploitValidationService
from secops.services.fingerprint import fingerprint_from_meta
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
            # Release sqlite writer lock before outbound CVE/API lookups.
            db.commit()
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
                # Keep the transaction short so worker lease heartbeats are not starved.
                db.commit()
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

    def _browser_candidate_urls(self, run: WorkspaceRun) -> list[str]:
        config = dict(run.config_json or {})
        browser_cfg = dict(config.get("browser") or {})
        explicit = str(browser_cfg.get("entry_url") or "").strip()
        target = str(run.target or "").strip()
        host = target
        if "://" in host:
            parsed = urlparse(host)
            host = parsed.hostname or host
        if ":" in host and not host.startswith("["):
            host = host.split(":", 1)[0]
        host = host.strip()
        candidates: list[str] = []
        if explicit:
            candidates.append(explicit)
        if host and "://" in target:
            candidates.append(target)
        ports = [str(port).strip() for port in (config.get("ports") or []) if str(port).strip().isdigit()]
        services = [str(item).lower() for item in (config.get("services") or []) if str(item).strip()]
        likely_web_ports = {"80", "443", "3000", "3001", "5000", "5173", "8000", "8080", "8443", "8888"}
        for port in ports:
            if port in likely_web_ports or int(port) >= 1024:
                scheme = "https" if port in {"443", "8443"} else "http"
                if host:
                    candidates.append(f"{scheme}://{host}:{port}")
        if any(token in " ".join(services) for token in ("http", "web", "nginx", "apache", "node", "nessus")) and host:
            if not ports:
                candidates.extend([f"http://{host}", f"http://{host}:3001", f"http://{host}:8080"])
        if host:
            candidates.extend([f"http://{host}", f"http://{host}:3001", f"http://{host}:8080"])
        deduped: list[str] = []
        seen: set[str] = set()
        for item in candidates:
            value = str(item or "").strip()
            if not value:
                continue
            if "://" not in value:
                value = f"http://{value}"
            if value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped

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
            candidate_urls = self._browser_candidate_urls(run)
            target_url = candidate_urls[0] if candidate_urls else str(((run.config_json or {}).get("browser") or {}).get("entry_url") or run.target or "").strip()
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
                payload={"agent": "browser", "candidates": candidate_urls[:8]},
                agent_session_id=session.id,
            )
            # Release sqlite write locks before long-running browser runtime activity.
            # Without this commit, heartbeat lease-renew writes can starve and mark the phase stale.
            run_config_snapshot = dict(run.config_json or {})
            db.commit()
            best_result = None
            best_url = target_url
            best_score = -1
            for idx, url in enumerate((candidate_urls or [target_url])[:8], start=1):
                cfg = dict(run_config_snapshot or {})
                browser_cfg = dict(cfg.get("browser") or {})
                browser_cfg["entry_url"] = url
                cfg["browser"] = browser_cfg
                current = self.browser.assess(
                    run_id=run.id,
                    workspace_root=paths.root,
                    target=url,
                    run_config=cfg,
                )
                score = (len(current.observations) * 10) + int(current.network_summary.get("total_requests") or 0) + len(current.route_graph)
                if score > best_score:
                    best_score = score
                    best_result = current
                    best_url = url
                if len(current.observations) > 0 and (len(current.route_graph) > 0 or int(current.network_summary.get("total_requests") or 0) > 3):
                    break
                if idx < len((candidate_urls or [target_url])[:8]):
                    self.events.emit(
                        db,
                        run.id,
                        "terminal",
                        f"[browser] candidate {url} yielded limited evidence; trying next target",
                        payload={"agent": "browser", "candidate": url},
                        agent_session_id=session.id,
                    )
            result = best_result if best_result is not None else self.browser.assess(
                run_id=run.id,
                workspace_root=paths.root,
                target=target_url,
                run_config=dict(run_config_snapshot or {}),
            )
            target_url = best_url
            config = dict(run.config_json or {})
            browser_cfg = dict(config.get("browser") or {})
            browser_cfg["entry_url"] = target_url
            config["browser"] = browser_cfg
            run.config_json = config
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
                if not self._is_meaningful_endpoint(value):
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
                endpoint_l = value.lower()
                endpoint_count = int(endpoint.get("count") or 0)
                endpoint_tokens = ("login", "auth", "admin", "password", "token", "search", "graphql", "config", "metrics", "upload", "reset")
                high_signal_tokens = ("admin", "auth", "password", "token", "config", "graphql")
                if any(token in endpoint_l for token in endpoint_tokens):
                    if endpoint_count < 2 and not any(token in endpoint_l for token in high_signal_tokens):
                        continue
                    title = f"API surface candidate: {value}"
                    if title not in emitted_vectors:
                        emitted_vectors.add(title)
                        severity = "high" if any(token in endpoint_l for token in high_signal_tokens) else "medium"
                        db.add(
                            self._browser_vector(
                                run_id=run.id,
                                title=title,
                                summary="Discovered browser-observed API endpoint requiring authorization and input validation checks.",
                                severity=severity,
                                evidence=f"Browser network summary observed endpoint pattern `{value}` with count={int(endpoint.get('count') or 0)}.",
                                tags=["browser", "api-endpoint"],
                                prerequisites=["authorization checks", "input validation checks"],
                                noise_level="quiet",
                                requires_approval=True,
                            )
                        )
            for route in route_values[:30]:
                route_l = route.lower()
                route_tokens = ("admin", "manage", "internal", "debug", "graphql", "swagger", "openapi")
                if any(token in route_l for token in route_tokens):
                    title = f"Route exposure candidate: {route}"
                    if title not in emitted_vectors:
                        emitted_vectors.add(title)
                        db.add(
                            self._browser_vector(
                                run_id=run.id,
                                title=title,
                                summary="Browser route discovery found an application path that warrants access-control and business-logic validation.",
                                severity="medium",
                                evidence=f"Browser discovered route `{route}`.",
                                tags=["browser", "route-surface"],
                                prerequisites=["route authorization validation"],
                                noise_level="quiet",
                                requires_approval=True,
                            )
                        )
            web_validation = self._browser_http_validations(
                base_url=target_url,
                network_endpoints=result.network_summary.get("endpoints", []),
                workspace_paths=paths,
            )
            category_validation = self._browser_category_validations(
                base_url=target_url,
                network_endpoints=result.network_summary.get("endpoints", []),
                workspace_paths=paths,
            )
            web_validation["findings"].extend(category_validation["findings"])
            web_validation["artifacts"].extend(category_validation["artifacts"])
            if web_validation["findings"]:
                existing_titles = {
                    str(row[0]).strip().lower()
                    for row in db.query(Finding.title).filter(Finding.run_id == run.id).all()
                    if str(row[0] or "").strip()
                }
                for finding in web_validation["findings"]:
                    title = str(finding.get("title") or "").strip()
                    if not title or title.lower() in existing_titles:
                        continue
                    existing_titles.add(title.lower())
                    db.add(
                        Finding(
                            run_id=run.id,
                            title=title[:255],
                            severity=str(finding.get("severity") or "medium"),
                            status="validated",
                            summary=str(finding.get("summary") or "")[:2000],
                            evidence=str(finding.get("evidence") or "")[:4000],
                            reproduction=str(finding.get("reproduction") or "")[:4000],
                            remediation=str(finding.get("remediation") or "")[:4000],
                            confidence=float(max(0.0, min(0.99, float(finding.get("confidence") or 0.75)))),
                        )
                    )
                for artifact_path in web_validation["artifacts"]:
                    db.add(
                        Artifact(
                            run_id=run.id,
                            kind="http-validation",
                            path=artifact_path,
                            metadata_json={"phase": "browser-assessment"},
                        )
                    )
                db.add(
                    RunMessage(
                        run_id=run.id,
                        role="system",
                        author="System",
                        content=f"Browser validation checks produced {len(web_validation['findings'])} validated finding(s).",
                        metadata_json={"phase": "browser-assessment", "validated_count": len(web_validation["findings"])},
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
            db.add(
                RunMessage(
                    run_id=run.id,
                    role="system",
                    author="System",
                    content=f"Browser vector generation: {len(emitted_vectors)} candidate vector(s) from browser evidence.",
                    metadata_json={"phase": "browser-assessment", "vector_count": len(emitted_vectors), "entry_url": target_url},
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

    def _browser_http_validations(self, *, base_url: str, network_endpoints: list[dict], workspace_paths) -> dict[str, list]:
        parsed = urlparse(str(base_url or ""))
        if not parsed.scheme or not parsed.netloc:
            return {"findings": [], "artifacts": []}
        origin = f"{parsed.scheme}://{parsed.netloc}"
        suspicious_tokens = (
            "admin",
            "config",
            "debug",
            "metrics",
            "swagger",
            "openapi",
            "graphql",
            "ftp",
            "backup",
            ".git",
            ".env",
            "internal",
        )
        static_suffixes = (".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")
        candidate_paths: list[str] = []
        for row in (network_endpoints or []):
            endpoint = str((row or {}).get("endpoint") or "").strip()
            if not endpoint:
                continue
            if not self._is_meaningful_endpoint(endpoint):
                continue
            parts = endpoint.split(" ", 1)
            if len(parts) != 2:
                continue
            method, path = parts[0].upper(), parts[1].strip()
            if method != "GET" or not path.startswith("/"):
                continue
            lower = path.lower()
            if lower.endswith(static_suffixes):
                continue
            if any(token in lower for token in suspicious_tokens):
                candidate_paths.append(path)
        deduped_paths: list[str] = []
        seen_paths: set[str] = set()
        for path in candidate_paths:
            if path in seen_paths:
                continue
            seen_paths.add(path)
            deduped_paths.append(path)

        findings: list[dict] = []
        artifacts: list[str] = []
        out_dir = workspace_paths.artifacts / "http-validation"
        out_dir.mkdir(parents=True, exist_ok=True)
        for path in deduped_paths[:12]:
            url = f"{origin}{path}"
            req = urlrequest.Request(url=url, method="GET")
            try:
                with urlrequest.urlopen(req, timeout=6) as resp:
                    status = int(getattr(resp, "status", 0) or 0)
                    ctype = str(resp.headers.get("Content-Type", "")).lower()
                    raw = resp.read(1400)
            except urlerror.HTTPError as exc:
                status = int(exc.code or 0)
                ctype = str(exc.headers.get("Content-Type", "")).lower() if exc.headers else ""
                raw = b""
            except Exception:
                continue
            if status != 200:
                continue
            snippet = raw.decode("utf-8", errors="ignore")[:800]
            lower_path = path.lower()
            sev = "medium"
            if any(token in lower_path for token in ("admin", "config", "debug", ".git", ".env", "backup", "internal", "ftp")):
                sev = "high"
            if "metrics" in lower_path:
                sev = "medium"
            title = f"Unauthenticated sensitive endpoint exposure: GET {path}"
            summary = f"Endpoint `{path}` returned HTTP 200 without authentication."
            remediation = "Require authentication and authorization checks for sensitive endpoints and files."
            if "metrics" in lower_path:
                remediation = "Restrict metrics endpoints to trusted networks and authenticated monitoring identities."
            slug = re.sub(r"[^a-zA-Z0-9]+", "-", path).strip("-")[:90] or "root"
            artifact_path = out_dir / f"{slug}.txt"
            artifact_path.write_text(
                f"URL: {url}\nStatus: {status}\nContent-Type: {ctype}\n\nSnippet:\n{snippet}\n",
                encoding="utf-8",
            )
            artifacts.append(str(artifact_path))
            findings.append(
                {
                    "title": title,
                    "severity": sev,
                    "summary": summary,
                    "evidence": f"{url} returned HTTP 200 unauthenticated. Artifact: {artifact_path}",
                    "reproduction": f"GET {url} without authentication",
                    "remediation": remediation,
                    "confidence": 0.82 if sev == "high" else 0.74,
                }
            )
            # Generic SQL error-based probe for query/search style endpoints.
            if any(token in lower_path for token in ("search", "query", "filter")):
                probe_url = f"{origin}{path}{'&' if '?' in path else '?'}q=%27"
                req_probe = urlrequest.Request(url=probe_url, method="GET")
                try:
                    with urlrequest.urlopen(req_probe, timeout=6) as probe_resp:
                        probe_status = int(getattr(probe_resp, "status", 0) or 0)
                        probe_raw = probe_resp.read(1400)
                except urlerror.HTTPError as exc:
                    probe_status = int(exc.code or 0)
                    probe_raw = b""
                except Exception:
                    probe_status = 0
                    probe_raw = b""
                probe_text = probe_raw.decode("utf-8", errors="ignore")
                sql_markers = ("sql", "sqlite", "syntax error", "unterminated", "sequelize", "database error")
                if probe_status >= 500 or any(marker in probe_text.lower() for marker in sql_markers):
                    sql_artifact = out_dir / f"{slug}-sqli-probe.txt"
                    sql_artifact.write_text(
                        f"URL: {probe_url}\nStatus: {probe_status}\n\nSnippet:\n{probe_text[:900]}\n",
                        encoding="utf-8",
                    )
                    artifacts.append(str(sql_artifact))
                    findings.append(
                        {
                            "title": f"Potential injection flaw at {path}",
                            "severity": "high",
                            "summary": "Input containing SQL metacharacters caused server/database error behavior.",
                            "evidence": f"Probe `{probe_url}` returned status={probe_status} with SQL-error-like response markers.",
                            "reproduction": f"GET {probe_url} and inspect response for database syntax errors.",
                            "remediation": "Use parameterized queries, strict input handling, and generic error responses.",
                            "confidence": 0.86,
                        }
                    )
        return {"findings": findings, "artifacts": artifacts}

    def _browser_category_validations(self, *, base_url: str, network_endpoints: list[dict], workspace_paths) -> dict[str, list]:
        parsed = urlparse(str(base_url or ""))
        if not parsed.scheme or not parsed.netloc:
            return {"findings": [], "artifacts": []}
        origin = f"{parsed.scheme}://{parsed.netloc}"
        endpoints = self._endpoint_paths(network_endpoints)
        out_dir = workspace_paths.artifacts / "http-validation"
        out_dir.mkdir(parents=True, exist_ok=True)
        findings: list[dict] = []
        artifacts: list[str] = []
        seen_titles: set[str] = set()

        def add_finding(item: dict) -> None:
            title = str(item.get("title") or "").strip()
            if not title or title.lower() in seen_titles:
                return
            seen_titles.add(title.lower())
            findings.append(item)

        exposure_checks = {
            "/metrics": ("medium", "Public metrics endpoint exposes runtime telemetry", "Restrict metrics to trusted monitoring networks or authenticated monitoring identities."),
            "/swagger.json": ("medium", "Public API schema disclosure", "Restrict machine-readable API schemas when they expose sensitive internal routes."),
            "/openapi.json": ("medium", "Public API schema disclosure", "Restrict machine-readable API schemas when they expose sensitive internal routes."),
            "/api-docs": ("medium", "Public API documentation exposure", "Restrict API documentation to trusted users or remove privileged routes from public docs."),
            "/.env": ("critical", "Environment file disclosure", "Remove environment files from web roots and rotate any exposed secrets."),
            "/.git/config": ("high", "Git metadata disclosure", "Block access to VCS metadata and remove repository internals from deployed web roots."),
        }
        for path, (severity, title, remediation) in exposure_checks.items():
            resp = self._http_request("GET", f"{origin}{path}", timeout=5)
            if resp["status"] != 200 or not resp["body"]:
                continue
            body_l = resp["body"].lower()
            if path == "/metrics" and "# help" not in body_l and "process_" not in body_l:
                continue
            if path in {"/swagger.json", "/openapi.json"} and "paths" not in body_l:
                continue
            if path == "/.env" and not re.search(r"(?m)^[A-Z0-9_]{3,}\s*=\s*.+$", resp["body"]):
                continue
            if path == "/.env" and self._looks_like_spa_html(resp):
                continue
            if path == "/.git/config" and "[core]" not in body_l and "repositoryformatversion" not in body_l:
                continue
            if path == "/.git/config" and self._looks_like_spa_html(resp):
                continue
            artifact = self._write_http_artifact(out_dir, path, resp, f"{origin}{path}")
            artifacts.append(str(artifact))
            add_finding(
                {
                    "title": title,
                    "severity": severity,
                    "summary": f"`{path}` returned HTTP 200 with sensitive operational content.",
                    "evidence": f"`GET {origin}{path}` returned HTTP 200. Artifact: {artifact}",
                    "reproduction": f"GET {origin}{path}",
                    "remediation": remediation,
                    "confidence": 0.84,
                }
            )

        sensitive_gets = sorted(
            {
                path
                for path in endpoints.get("GET", set())
                if any(token in path.lower() for token in ("admin", "config", "version", "memory", "memories", "users", "metrics", "ftp", "backup"))
            }
        )
        for fallback in ("/rest/memories", "/rest/memories/", "/api/Users", "/ftp/", "/ftp/acquisitions.md", "/backup", "/admin"):
            if fallback not in sensitive_gets:
                sensitive_gets.append(fallback)
        deduped_sensitive_gets: list[str] = []
        seen_sensitive_keys: set[str] = set()
        for path in sensitive_gets:
            key = path.rstrip("/") or path
            if key in seen_sensitive_keys:
                continue
            seen_sensitive_keys.add(key)
            deduped_sensitive_gets.append(path)
        for path in deduped_sensitive_gets[:20]:
            resp = self._http_request("GET", f"{origin}{path}", timeout=5)
            if resp["status"] != 200:
                continue
            if self._looks_like_spa_html(resp):
                continue
            artifact = self._write_http_artifact(out_dir, path, resp, f"{origin}{path}")
            artifacts.append(str(artifact))
            severity = "high" if any(token in path.lower() for token in ("admin", "config", "users", "memory", "memories", "backup")) else "medium"
            add_finding(
                {
                    "title": f"Unauthenticated sensitive endpoint exposure: GET {path}",
                    "severity": severity,
                    "summary": f"Sensitive-looking endpoint `{path}` returned HTTP 200 without authentication.",
                    "evidence": f"`GET {origin}{path}` returned HTTP 200. Artifact: {artifact}",
                    "reproduction": f"GET {origin}{path}",
                    "remediation": "Require authentication and object-level authorization for sensitive API and file endpoints.",
                    "confidence": 0.82,
                }
            )

        login_candidates = sorted(path for path in endpoints.get("POST", set()) if any(token in path.lower() for token in ("login", "signin", "auth")))
        for fallback in ("/rest/user/login", "/api/login", "/login", "/auth/login", "/users/login"):
            if fallback not in login_candidates:
                login_candidates.append(fallback)
        for path in login_candidates[:5]:
            probe = {"email": "' OR 1=1--", "username": "' OR 1=1--", "password": "anything"}
            resp = self._http_request("POST", f"{origin}{path}", json_body=probe, timeout=6)
            body_l = resp["body"].lower()
            if resp["status"] == 200 and any(token in body_l for token in ("token", "jwt", "auth", "admin", "role")):
                artifact = self._write_http_artifact(out_dir, f"{path}-sqli-auth-bypass", resp, f"{origin}{path}", request_body=probe)
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": f"SQL injection authentication bypass: POST {path}",
                        "severity": "critical",
                        "summary": "Authentication accepted a SQL tautology payload and returned an authenticated-looking response.",
                        "evidence": f"`POST {origin}{path}` with a SQL tautology returned HTTP 200 and authentication markers. Artifact: {artifact}",
                        "reproduction": f"POST {origin}{path} with JSON email/username payload `' OR 1=1--` and any password.",
                        "remediation": "Use parameterized queries or ORM-safe predicates for authentication and add negative tests for SQL metacharacters.",
                        "confidence": 0.93,
                    }
                )

        query_candidates = sorted(
            {
                path
                for method, paths in endpoints.items()
                for path in paths
                if method == "GET" and any(token in path.lower() for token in ("search", "query", "filter", "lookup"))
            }
        )
        for path in query_candidates[:10]:
            probe_path = self._append_query(path, {"q": "'"})
            resp = self._http_request("GET", f"{origin}{probe_path}", timeout=6)
            body_l = resp["body"].lower()
            if resp["status"] >= 500 or any(token in body_l for token in ("sql", "sqlite", "syntax error", "sequelize", "database error")):
                artifact = self._write_http_artifact(out_dir, f"{path}-sqli-error", resp, f"{origin}{probe_path}")
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": f"Error-based injection signal: GET {path}",
                        "severity": "high",
                        "summary": "SQL metacharacter input produced server/database error behavior on a query endpoint.",
                        "evidence": f"`GET {origin}{probe_path}` returned status={resp['status']} with database-error markers. Artifact: {artifact}",
                        "reproduction": f"GET {origin}{probe_path}",
                        "remediation": "Use parameterized queries, strict input handling, and generic error responses.",
                        "confidence": 0.84,
                    }
                )

        jsonp_candidates = sorted(path for method, paths in endpoints.items() for path in paths if method == "GET" and "whoami" in path.lower())
        for path in jsonp_candidates[:5]:
            probe_path = self._append_query(path, {"callback": "alert"})
            resp = self._http_request("GET", f"{origin}{probe_path}", timeout=5)
            body = resp["body"]
            if resp["status"] == 200 and ("alert(" in body or "typeof alert" in body):
                artifact = self._write_http_artifact(out_dir, f"{path}-jsonp-callback", resp, f"{origin}{probe_path}")
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": f"JSONP callback execution surface: GET {path}",
                        "severity": "medium",
                        "summary": "The endpoint reflects a callback name into executable JavaScript-style response content.",
                        "evidence": f"`GET {origin}{probe_path}` returned callback execution markers. Artifact: {artifact}",
                        "reproduction": f"GET {origin}{probe_path}",
                        "remediation": "Remove JSONP support where possible; otherwise restrict callback names and return JSON with CORS controls.",
                        "confidence": 0.8,
                    }
                )

        upload_or_url_paths = sorted(
            {
                path
                for method, paths in endpoints.items()
                for path in paths
                if any(token in path.lower() for token in ("image/url", "profile/image", "fetch", "import", "webhook", "callback", "avatar"))
            }
        )
        for path in upload_or_url_paths[:10]:
            add_finding(
                {
                    "title": f"SSRF validation candidate: {path}",
                    "severity": "medium",
                    "summary": "Browser/API discovery found a URL-ingestion style endpoint requiring SSRF validation.",
                    "evidence": f"Discovered URL-ingestion style endpoint `{path}` during browser/network assessment.",
                    "reproduction": f"Review accepted URL parameters on {origin}{path} and validate with non-destructive internal canary URLs.",
                    "remediation": "Enforce URL allowlists, block private/link-local ranges, and fetch remote content through hardened proxy controls.",
                    "confidence": 0.62,
                }
            )

        return {"findings": findings, "artifacts": artifacts}

    def _endpoint_paths(self, network_endpoints: list[dict]) -> dict[str, set[str]]:
        endpoints: dict[str, set[str]] = {}
        for row in network_endpoints or []:
            raw = str((row or {}).get("endpoint") or "").strip()
            if not self._is_meaningful_endpoint(raw):
                continue
            method, path = raw.split(" ", 1)
            endpoints.setdefault(method.upper(), set()).add(path.strip())
        return endpoints

    def _append_query(self, path: str, params: dict[str, str]) -> str:
        sep = "&" if "?" in path else "?"
        return f"{path}{sep}{urlencode(params)}"

    def _http_request(self, method: str, url: str, *, json_body: dict | None = None, timeout: int = 5) -> dict[str, str | int]:
        body_bytes = None
        headers = {"User-Agent": "Vantix-Validation/1.0"}
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urlrequest.Request(url=url, data=body_bytes, method=method.upper(), headers=headers)
        try:
            with urlrequest.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(20000)
                return {
                    "status": int(getattr(resp, "status", 0) or 0),
                    "headers": "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                    "body": raw.decode("utf-8", errors="ignore"),
                }
        except urlerror.HTTPError as exc:
            raw = exc.read(20000) if hasattr(exc, "read") else b""
            return {
                "status": int(exc.code or 0),
                "headers": "\n".join(f"{k}: {v}" for k, v in exc.headers.items()) if exc.headers else "",
                "body": raw.decode("utf-8", errors="ignore"),
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": 0, "headers": "", "body": f"request failed: {exc}"}

    def _looks_like_spa_html(self, response: dict[str, str | int]) -> bool:
        headers = str(response.get("headers") or "").lower()
        body = str(response.get("body") or "").lower()[:1200]
        return "content-type: text/html" in headers and ("<!doctype html" in body or "<html" in body)

    def _write_http_artifact(
        self,
        out_dir: Path,
        path: str,
        response: dict[str, str | int],
        url: str,
        *,
        request_body: dict | None = None,
    ) -> Path:
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", path).strip("-")[:110] or "http"
        artifact_path = out_dir / f"{slug}.txt"
        body = str(response.get("body") or "")
        headers = str(response.get("headers") or "")
        request_block = ""
        if request_body is not None:
            request_block = f"\nRequest JSON:\n{json.dumps(request_body, indent=2)}\n"
        artifact_path.write_text(
            f"URL: {url}\nStatus: {response.get('status')}\nHeaders:\n{headers[:2000]}\n{request_block}\nBody Snippet:\n{body[:6000]}\n",
            encoding="utf-8",
        )
        return artifact_path

    def _is_meaningful_endpoint(self, endpoint: str) -> bool:
        value = str(endpoint or "").strip()
        if not value:
            return False
        parts = value.split(" ", 1)
        if len(parts) != 2:
            return False
        method, path = parts[0].upper().strip(), parts[1].strip()
        if not path.startswith("/"):
            return False
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            return False
        lower = path.lower()
        noisy_prefixes = (
            "/assets/",
            "/dist/",
            "/static/",
            "/socket.io/",
            "/github/collect",
            "/favicon",
        )
        if any(lower.startswith(prefix) for prefix in noisy_prefixes):
            return False
        noisy_suffixes = (
            ".css",
            ".js",
            ".mjs",
            ".map",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".webp",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
        )
        if lower.endswith(noisy_suffixes):
            return False
        if "/images/uploads/" in lower:
            return False
        return True

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
                        stripped = line.strip()
                        if not stripped:
                            return
                        noisy_prefixes = (
                            "### /home/",
                            "id=mem.",
                            "ts=",
                            "fmt: id=<id>",
                            "load: use `python3 scripts/learn_engine.py",
                            "OpenAI Codex v",
                            "workdir:",
                            "model:",
                            "provider:",
                            "approval:",
                            "sandbox:",
                            "reasoning effort:",
                            "reasoning summaries:",
                            "session id:",
                            "--------",
                        )
                        if stripped.startswith(noisy_prefixes):
                            return
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
                if result.returncode == 0:
                    self._sweep_orchestrator_vectors(db, run, session_started_at=session.started_at)
                db.commit()

    def _sweep_orchestrator_vectors(self, db, run: WorkspaceRun, *, session_started_at) -> None:
        """Post-orchestrate: fingerprint vectors and replay any with a validation spec.

        Vectors without a `replay` spec in their metadata stay kind=vector but
        validated=False, so they will not promote when SECOPS_REQUIRE_VALIDATED_PROMOTION
        is enabled. Vectors with a spec are replayed via ExploitValidationService,
        which marks validated=True on success or writes a negative_evidence Fact
        with a matching fingerprint on failure.
        """
        cutoff = session_started_at
        q = (
            db.query(Fact)
            .filter(
                Fact.run_id == run.id,
                Fact.kind.in_(["vector", "vector_hypothesis"]),
            )
        )
        if cutoff is not None:
            q = q.filter(Fact.created_at >= cutoff)
        vectors = q.all()
        if not vectors:
            return
        validator = ExploitValidationService()
        for fact in vectors:
            meta = dict(fact.metadata_json or {})
            if not fact.fingerprint:
                fact.fingerprint = fingerprint_from_meta(meta, fact_kind=fact.kind)
            replay = meta.get("replay")
            if not (isinstance(replay, dict) and replay.get("type") == "http"):
                continue
            if fact.validated:
                continue
            try:
                validator.validate_vector(db, run, fact)
            except Exception as exc:  # noqa: BLE001
                self.events.emit(
                    db,
                    run.id,
                    "terminal",
                    f"Exploit validation raised for fact {fact.id[:8]}: {exc}",
                    level="warning",
                )
        db.flush()

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
            workspace = self.nas.for_workspace(run.workspace_id)
            adopted = self._existing_report_package(workspace)
            if adopted:
                self._ensure_findings_for_report(db, run)
                generated = adopted
            else:
                self._ensure_findings_for_report(db, run)
                generated = self.reporting.generate(db, run)
            task.status = "completed"
            self._set_role_status(db, run.id, "reporter", "completed")
            self._set_vantix_task_status(db, run.id, "reporting", "completed", {"source_phase": "report"})
            task.result_json = {
                "report_path": generated["markdown_path"],
                "report_json_path": generated["json_path"],
                "comprehensive_report_path": generated.get("comprehensive_markdown_path", ""),
                "comprehensive_report_json_path": generated.get("comprehensive_json_path", ""),
                "artifact_index_path": generated.get("artifact_index_path", ""),
                "timeline_csv_path": generated.get("timeline_csv_path", ""),
            }
            db.add(
                Artifact(
                    run_id=run.id,
                    kind="report",
                    path=str(generated["markdown_path"]),
                    metadata_json={"report_json_path": generated["json_path"]},
                )
            )
            db.add(Artifact(run_id=run.id, kind="report-json", path=str(generated["json_path"]), metadata_json={}))
            if generated.get("comprehensive_markdown_path"):
                db.add(
                    Artifact(
                        run_id=run.id,
                        kind="comprehensive-report",
                        path=str(generated["comprehensive_markdown_path"]),
                        metadata_json={},
                    )
                )
            if generated.get("comprehensive_json_path"):
                db.add(
                    Artifact(
                        run_id=run.id,
                        kind="comprehensive-report-json",
                        path=str(generated["comprehensive_json_path"]),
                        metadata_json={},
                    )
                )
            if generated.get("artifact_index_path"):
                db.add(Artifact(run_id=run.id, kind="artifact-index", path=str(generated["artifact_index_path"]), metadata_json={}))
            if generated.get("timeline_csv_path"):
                db.add(Artifact(run_id=run.id, kind="timeline-csv", path=str(generated["timeline_csv_path"]), metadata_json={}))
            self.events.emit(
                db,
                run.id,
                "phase",
                "Report generated",
                payload={
                    "phase": "report",
                    "report_path": generated["markdown_path"],
                    "report_json_path": generated["json_path"],
                    "comprehensive_report_path": generated.get("comprehensive_markdown_path", ""),
                    "artifact_index_path": generated.get("artifact_index_path", ""),
                    "timeline_csv_path": generated.get("timeline_csv_path", ""),
                },
            )
            db.add(
                RunMessage(
                    run_id=run.id,
                    role="system",
                    author="System",
                    content=f"Report package generated: {generated['markdown_path']}",
                    metadata_json={
                        "phase": "report",
                        "report_path": generated["markdown_path"],
                        "report_json_path": generated["json_path"],
                        "comprehensive_report_path": generated.get("comprehensive_markdown_path", ""),
                        "comprehensive_report_json_path": generated.get("comprehensive_json_path", ""),
                        "artifact_index_path": generated.get("artifact_index_path", ""),
                        "timeline_csv_path": generated.get("timeline_csv_path", ""),
                    },
                )
            )
            file_paths = [
                str(generated["markdown_path"]),
                str(generated["json_path"]),
                str(generated.get("comprehensive_markdown_path", "")),
                str(generated.get("comprehensive_json_path", "")),
                str(generated.get("artifact_index_path", "")),
                str(generated.get("timeline_csv_path", "")),
            ]
            self._write_memory(
                db,
                run,
                mode="phase",
                phase="report",
                done=["report package generated"],
                files=[path for path in file_paths if path],
                next_action="close run",
            )
            db.commit()

    def _existing_report_package(self, workspace) -> dict[str, str] | None:
        report_md = workspace.artifacts / "run_report.md"
        report_json = workspace.artifacts / "run_report.json"
        if not report_md.exists() or not report_json.exists():
            return None
        try:
            payload = json.loads(report_json.read_text(encoding="utf-8", errors="ignore"))
        except Exception:  # noqa: BLE001
            return None
        findings = payload.get("findings") or []
        if not isinstance(findings, list) or len(findings) == 0:
            return None
        return {
            "markdown_path": str(report_md),
            "json_path": str(report_json),
            "comprehensive_markdown_path": str(workspace.artifacts / "comprehensive_security_assessment_report.md")
            if (workspace.artifacts / "comprehensive_security_assessment_report.md").exists()
            else "",
            "comprehensive_json_path": str(workspace.artifacts / "comprehensive_security_assessment_report.json")
            if (workspace.artifacts / "comprehensive_security_assessment_report.json").exists()
            else "",
            "artifact_index_path": str(workspace.artifacts / "artifact_index.json")
            if (workspace.artifacts / "artifact_index.json").exists()
            else "",
            "timeline_csv_path": str(workspace.artifacts / "timeline.csv")
            if (workspace.artifacts / "timeline.csv").exists()
            else "",
        }

    def _ensure_findings_for_report(self, db, run: WorkspaceRun | str) -> None:
        if isinstance(run, str):
            resolved = db.get(WorkspaceRun, run)
            if resolved is None:
                return
            run = resolved
        run_id = run.id
        existing_titles = {
            str(row[0]).strip().lower()
            for row in db.query(Finding.title).filter(Finding.run_id == run_id).all()
            if str(row[0] or "").strip()
        }
        created = 0

        # Prefer validated findings from generated report JSON when present.
        workspace = self.nas.for_workspace(run.workspace_id)
        report_paths = [
            workspace.artifacts / "run_report.json",
            workspace.artifacts / "comprehensive_security_assessment_report.json",
        ]
        for report_path in report_paths:
            if not report_path.exists():
                continue
            try:
                payload = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:  # noqa: BLE001
                continue
            for item in (payload.get("findings") or []):
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title") or "").strip()[:255]
                if not title:
                    continue
                key = title.lower()
                if key in existing_titles:
                    continue
                severity = str(item.get("severity") or "medium").lower().strip()
                severity_map = {"low-medium": "medium", "med": "medium", "informational": "info"}
                severity = severity_map.get(severity, severity)
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "medium"
                status = str(item.get("status") or "validated").lower().strip()
                if status not in {"validated", "candidate", "confirmed", "fixed", "rejected"}:
                    status = "validated"
                summary = str(item.get("summary") or item.get("overview") or title).strip()[:2000]
                evidence_value = item.get("evidence")
                if isinstance(evidence_value, list):
                    evidence = "\n".join(str(v).strip() for v in evidence_value if str(v).strip())[:4000]
                else:
                    evidence = str(evidence_value or "").strip()[:4000]
                reproduction = str(item.get("reproduction") or item.get("steps") or "").strip()[:4000]
                remediation = str(item.get("remediation") or item.get("fix") or "").strip()[:4000]
                raw_conf = item.get("confidence")
                if isinstance(raw_conf, (int, float)):
                    confidence = float(max(0.0, min(0.99, float(raw_conf))))
                else:
                    confidence = {
                        "critical": 0.95,
                        "high": 0.85,
                        "medium": 0.7,
                        "low": 0.6,
                        "info": 0.5,
                    }.get(severity, 0.7)
                db.add(
                    Finding(
                        run_id=run_id,
                        title=title,
                        severity=severity,
                        status=status,
                        summary=summary,
                        evidence=evidence,
                        reproduction=reproduction,
                        remediation=remediation,
                        confidence=confidence,
                    )
                )
                existing_titles.add(key)
                created += 1

        # Pull validated findings from operator-authored pentest summaries.
        summary_path = workspace.artifacts / "pentest-summary.md"
        if summary_path.exists():
            for item in self._parse_pentest_summary_findings(summary_path):
                title = str(item.get("title") or "").strip()[:255]
                if not title:
                    continue
                key = title.lower()
                if key in existing_titles:
                    continue
                severity = str(item.get("severity") or "medium").lower().strip()
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "medium"
                db.add(
                    Finding(
                        run_id=run_id,
                        title=title,
                        severity=severity,
                        status="validated",
                        summary=str(item.get("summary") or title).strip()[:2000],
                        evidence=str(item.get("evidence") or "").strip()[:4000],
                        reproduction="Reproduce using the recorded endpoint and payload path in pentest-summary evidence.",
                        remediation=str(item.get("remediation") or "").strip()[:4000],
                        confidence=float(item.get("confidence") or 0.8),
                    )
                )
                existing_titles.add(key)
                created += 1

        vectors = (
            db.query(Fact)
            .filter(Fact.run_id == run_id, Fact.kind == "vector")
            .order_by(Fact.confidence.desc(), Fact.created_at.asc())
            .all()
        )
        promoted = 0
        for vector in vectors:
            meta = dict(vector.metadata_json or {})
            status = str(meta.get("status") or "").lower()
            confidence = float(meta.get("score") or vector.confidence or 0.0)
            evidence = str(meta.get("evidence") or vector.value or "").strip()
            if status not in {"planned", "validated", "selected", "executed"} and confidence < 0.7:
                continue
            if status == "candidate":
                continue
            if confidence < 0.7:
                continue
            if not evidence:
                continue
            title = str(meta.get("title") or vector.value or "Vector-derived finding").strip()[:255]
            if not title:
                continue
            if title.lower() in existing_titles:
                continue
            summary = str(meta.get("summary") or "Vector selected for validation during workflow execution.").strip()
            severity = str(meta.get("severity") or "medium").lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "medium"
            db.add(
                Finding(
                    run_id=run_id,
                    title=title,
                    severity=severity,
                    status="validated",
                    summary=summary[:2000],
                    evidence=evidence[:4000],
                    reproduction=str(meta.get("next_action") or "").strip()[:4000],
                    remediation="Validate, patch, and retest based on captured evidence.",
                    confidence=max(0.0, min(0.99, confidence)),
                )
            )
            existing_titles.add(title.lower())
            promoted += 1
            created += 1
            if promoted >= 10:
                break

    def _parse_pentest_summary_findings(self, summary_path: Path) -> list[dict[str, str | float]]:
        try:
            content = summary_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return []
        marker = "## Validated Findings"
        if marker not in content:
            return []
        section = content.split(marker, 1)[1]
        raw_blocks = re.split(r"\n###\s+", section)
        findings: list[dict[str, str | float]] = []
        for raw in raw_blocks:
            block = raw.strip()
            if not block:
                continue
            first_line, _, rest = block.partition("\n")
            heading = first_line.strip()
            if not heading:
                continue
            severity = "medium"
            title = heading
            if ":" in heading:
                maybe_sev, maybe_title = heading.split(":", 1)
                sev_norm = maybe_sev.strip().lower()
                if sev_norm in {"critical", "high", "medium", "low", "info"}:
                    severity = sev_norm
                    title = maybe_title.strip()
            body = rest.strip()
            if not body:
                continue
            summary_lines: list[str] = []
            evidence_lines: list[str] = []
            remediation_lines: list[str] = []
            mode = "summary"
            for line in body.splitlines():
                text = line.strip()
                if not text:
                    continue
                lower = text.lower()
                if lower.startswith("evidence:"):
                    mode = "evidence"
                    continue
                if lower.startswith("recommendation:"):
                    mode = "remediation"
                    continue
                if mode == "summary":
                    summary_lines.append(text)
                elif mode == "evidence":
                    evidence_lines.append(text.lstrip("- ").strip())
                else:
                    remediation_lines.append(text)
            summary = " ".join(summary_lines).strip()
            evidence = "\n".join(line for line in evidence_lines if line)
            remediation = " ".join(remediation_lines).strip()
            if not summary:
                summary = f"Validated finding captured in {summary_path.name}."
            findings.append(
                {
                    "title": title[:255],
                    "severity": severity,
                    "summary": summary[:2000],
                    "evidence": evidence[:4000],
                    "remediation": remediation[:4000],
                    "confidence": {
                        "critical": 0.95,
                        "high": 0.88,
                        "medium": 0.78,
                        "low": 0.68,
                        "info": 0.6,
                    }.get(severity, 0.78),
                }
            )
        return findings

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
