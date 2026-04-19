from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
import json
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
from secops.services.storage import StorageLayout
from secops.services.worker_runtime import worker_runtime
from secops.services.workflows.engine import WorkflowEngine


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
            self.events.emit(db, run.id, "phase", f"Learning recall completed: {len(results)} hits")
            self._write_memory(db, run, mode="phase", phase="learning-recall", done=[f"learning hits={len(results)}"], files=[str(paths.facts / "learning_hits.json")], next_action="recon sidecar")
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
            command = []
            recon_target = self._recon_target(run.target)
            if recon_target:
                if run.config_json.get("ports"):
                    ports = ",".join(run.config_json["ports"])
                    command = ["nmap", "-Pn", "-sT", "-p", ports, "--open", recon_target]
                else:
                    command = ["nmap", "-Pn", "-sT", "--top-ports", "100", "--open", recon_target]
            output = self._run_command(command, session.log_path, run=run) if command else "No target supplied; recon skipped.\n"
            paths.write_text(Path(session.log_path), output)
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
            task.status = "completed"
            task.result_json = discovered
            self.events.emit(db, run.id, "phase", "Recon completed", payload=discovered, agent_session_id=session.id)
            facts = [[ "port", port ] for port in discovered["ports"]] + [[ "service", service ] for service in discovered["services"]]
            self._write_memory(db, run, mode="phase", phase="recon", done=["recon completed"], facts=facts, files=[str(session.log_path)], next_action="cve analysis")
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
            paths = self.nas.for_workspace(run.workspace_id)
            session = self._create_agent_session(db, run.id, "research", "CVE Research Sidecar", paths)
            results = []
            services = run.config_json.get("services", [])
            for service in services:
                response = self.cve.search(vendor=service, product=service)
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
            task.status = "completed"
            task.result_json = {"queries": len(results)}
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
            db.flush()
            self.events.emit(db, run.id, "phase", "Primary orchestration started", agent_session_id=session.id)
            self._write_memory(db, run, mode="phase", phase="orchestrate-start", done=["primary orchestration started"], files=[str(prompt_path)], next_action="monitor orchestrator")
            db.commit()

            log_path = Path(session.log_path)
            codex_policy = self.policies.evaluate(run, action_kind="codex")
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
                    task = self._task_by_kind(inner_db, run.id, "orchestrate")
                    task.status = "completed" if result.returncode == 0 else "failed"
                    task.result_json = {"returncode": result.returncode}
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
            paths = self.nas.for_workspace(run.workspace_id)
            facts = db.execute(select(Fact).where(Fact.run_id == run.id)).scalars().all()
            events = db.execute(select(Artifact).where(Artifact.run_id == run.id)).scalars().all()
            report = [
                f"# Run Summary: {run.workspace_id}",
                "",
                f"- Mode: {run.mode}",
                f"- Target: {run.target}",
                f"- Objective: {run.objective}",
                "",
                "## Facts",
            ]
            for fact in facts[:50]:
                report.append(f"- [{fact.kind}] {fact.value} (confidence={fact.confidence})")
            report.extend(["", "## Artifacts"])
            for artifact in events:
                report.append(f"- {artifact.kind}: {artifact.path}")
            report_path = paths.artifacts / "run_summary.md"
            paths.write_text(report_path, "\n".join(report) + "\n")
            task.status = "completed"
            task.result_json = {"report_path": str(report_path)}
            db.add(Artifact(run_id=run.id, kind="report", path=str(report_path), metadata_json={}))
            self.events.emit(db, run.id, "phase", "Report generated")
            self._write_memory(db, run, mode="phase", phase="report", done=["report generated"], files=[str(report_path)], next_action="close run")
            db.commit()

    def _task_by_kind(self, db, run_id: str, kind: str) -> Task:
        return db.execute(select(Task).where(Task.run_id == run_id, Task.kind == kind)).scalar_one()

    def _create_agent_session(self, db, run_id: str, role: str, name: str, paths) -> AgentSession:
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
        return session

    def _create_approval(self, db, run_id: str, title: str, detail: str, reason: str) -> ApprovalRequest:
        approval = ApprovalRequest(run_id=run_id, title=title, detail=detail, reason=reason, status="pending")
        db.add(approval)
        self.events.emit(db, run_id, "approval", title, level="warning", payload={"reason": reason})
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

    def _run_command(self, command: list[str], log_path: str, *, run: WorkspaceRun | None = None) -> str:
        if not command:
            return ""
        if run is not None:
            decision = self.policies.evaluate(run, action_kind="script")
            if decision.verdict in {"block", "require_approval"}:
                return f"Command blocked by policy: {decision.reason}\n"
        record = self.policies.run_subprocess(command, timeout_seconds=120, redactions=[settings.secret_key])
        output = (record.stdout or "") + ("\n" + record.stderr if record.stderr else "")
        if record.timed_out:
            return output + "\nCommand timed out.\n"
        if record.error_class and record.returncode != 0:
            return output + f"\nCommand failed ({record.error_class}) rc={record.returncode}.\n"
        return output

    def _parse_nmap(self, output: str) -> dict[str, list[str]]:
        ports = re.findall(r"(?m)^(\d{1,5})/tcp\s+open", output)
        services = re.findall(r"(?m)^\d{1,5}/tcp\s+open\s+([a-zA-Z0-9_.-]+)", output)
        return {"ports": sorted(set(ports)), "services": sorted(set(services))}


execution_manager = ExecutionManager()
