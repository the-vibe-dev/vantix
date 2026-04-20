from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from secops.config import settings
from secops.models import (
    Action,
    Artifact,
    Engagement,
    Task,
    WorkerLease,
    WorkflowExecution,
    WorkflowPhaseRun,
    WorkspaceRun,
)
from secops.mode_profiles import get_mode_profile
from secops.services.codex_runner import CodexRunner
from secops.services.context_builder import ContextBuilder
from secops.services.storage import StorageLayout


class RunService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.context_builder = ContextBuilder()
        self.nas = StorageLayout()

    def create_run(
        self,
        engagement_id: str,
        objective: str,
        target: str,
        ports: list[str],
        services: list[str],
        tags: list[str],
        config: dict,
    ) -> WorkspaceRun:
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise ValueError(f"Engagement not found: {engagement_id}")

        workspace_id = f"{engagement.mode}-{uuid4().hex[:12]}"
        run = WorkspaceRun(
            engagement_id=engagement.id,
            mode=engagement.mode,
            workspace_id=workspace_id,
            status="planned",
            objective=objective,
            repo_path=str(settings.repo_root),
            target=target or engagement.target,
            config_json={
                **config,
                "ports": ports,
                "services": services,
                "tags": tags,
            },
        )
        self.db.add(run)
        self.db.flush()

        self._seed_default_tasks(run)
        self._materialize_context_artifact(run, ports=ports, services=services, tags=tags)
        self.db.commit()
        self.db.refresh(run)
        return run

    def resume_run(self, run_id: str) -> WorkspaceRun:
        previous = self.db.get(WorkspaceRun, run_id)
        if previous is None:
            raise ValueError(f"Run not found: {run_id}")
        new_run = WorkspaceRun(
            engagement_id=previous.engagement_id,
            mode=previous.mode,
            workspace_id=f"{previous.mode}-{uuid4().hex[:12]}",
            status="planned",
            objective=previous.objective,
            repo_path=previous.repo_path,
            target=previous.target,
            config_json=previous.config_json,
            resumed_from_run_id=previous.id,
        )
        self.db.add(new_run)
        self.db.flush()

        incomplete_tasks = (
            self.db.execute(
                select(Task).where(Task.run_id == previous.id, Task.status.in_(["pending", "running", "planned"]))
            )
            .scalars()
            .all()
        )
        for task in incomplete_tasks:
            self.db.add(
                Task(
                    run_id=new_run.id,
                    name=task.name,
                    description=task.description,
                    kind=task.kind,
                    status="pending",
                    sequence=task.sequence,
                    context_json=task.context_json,
                )
            )
        self._materialize_context_artifact(
            new_run,
            ports=previous.config_json.get("ports", []),
            services=previous.config_json.get("services", []),
            tags=previous.config_json.get("tags", []),
        )
        self.db.commit()
        self.db.refresh(new_run)
        return new_run

    def retry_run(self, run_id: str, *, replan: bool = False) -> WorkspaceRun:
        """Reset workflow + phase + lease state so the engine can re-run this run.

        - Marks pending/running phases as cancelled.
        - Finalizes active leases as released.
        - Flips the latest WorkflowExecution back to queued.
        - For replan: clears Task rows and re-seeds the default task plan.
        """
        run = self.db.get(WorkspaceRun, run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")

        # Release active leases (worker stale / current).
        leases = (
            self.db.query(WorkerLease)
            .filter(WorkerLease.run_id == run_id, WorkerLease.status == "active")
            .all()
        )
        for lease in leases:
            lease.status = "released"

        # Cancel any phases still in-flight or queued.
        phases = (
            self.db.query(WorkflowPhaseRun)
            .filter(
                WorkflowPhaseRun.run_id == run_id,
                WorkflowPhaseRun.status.in_(["pending", "claimed", "retrying", "blocked"]),
            )
            .all()
        )
        for phase in phases:
            phase.status = "cancelled"

        # Reset the active workflow execution back to queued so the engine picks it up.
        workflow = (
            self.db.query(WorkflowExecution)
            .filter(WorkflowExecution.run_id == run_id)
            .order_by(WorkflowExecution.created_at.desc())
            .first()
        )
        if workflow is not None:
            workflow.status = "queued"
            workflow.current_phase = ""

        if replan:
            self.db.query(Task).filter(Task.run_id == run_id).delete(synchronize_session=False)
            self.db.flush()
            self._seed_default_tasks(run)
            self._materialize_context_artifact(
                run,
                ports=list(run.config_json.get("ports", [])),
                services=list(run.config_json.get("services", [])),
                tags=list(run.config_json.get("tags", [])),
            )

        run.status = "queued"
        self.db.commit()
        self.db.refresh(run)
        return run

    def _seed_default_tasks(self, run: WorkspaceRun) -> None:
        tasks = [
            ("context-bootstrap", "Assemble mode-specific Codex startup context and learning digest."),
            ("source-intake", "Resolve source input (GitHub/local/upload) for white-box analysis."),
            ("source-analysis", "Run source-level analysis and emit white-box findings."),
            ("learning-recall", "Recall relevant lessons across the whole system with mode-aware ranking."),
            ("recon-sidecar", "Dispatch the recon sidecar and persist its outcome."),
            ("browser-assessment", "Run browser-native route/form/API/session discovery with policy controls."),
            ("cve-analysis", "Re-check CVEs based on configured or discovered services."),
            ("orchestrate", "Run the primary Codex orchestrator against the current target state."),
            ("learn-ingest", "Ingest run artifacts back into the learning system."),
            ("report", "Generate the run summary and indexed artifacts."),
        ]
        for sequence, (kind, description) in enumerate(tasks, start=1):
            task = Task(
                run_id=run.id,
                name=kind.replace("-", " ").title(),
                description=description,
                kind=kind,
                status="pending",
                sequence=sequence,
            )
            self.db.add(task)
        self.db.flush()

        codex_task = self.db.execute(
            select(Task).where(Task.run_id == run.id, Task.kind == "orchestrate")
        ).scalar_one()
        self.db.add(
            Action(
                task_id=codex_task.id,
                name="Run primary Codex orchestrator",
                tool="codex",
                command="codex exec ...",
                status="planned",
            )
        )
        self.db.flush()

    def _materialize_context_artifact(
        self,
        run: WorkspaceRun,
        ports: list[str],
        services: list[str],
        tags: list[str],
    ) -> None:
        profile = get_mode_profile(run.mode)
        bundle = self.context_builder.build(
            profile,
            target=run.target,
            ports=ports,
            services=services,
            extra_tags=tags,
        )
        run_paths = self.nas.for_workspace(run.workspace_id)
        workspace_dir = run_paths.agents / "orchestrator"
        runner = CodexRunner(workspace_dir=workspace_dir)
        codex_bin = runner.resolve_binary() or settings.codex_bin
        shell_preview = (
            f"{codex_bin} exec --model {settings.default_model} "
            "--dangerously-bypass-approvals-and-sandbox '<prompt>'"
        )

        context_task = self.db.execute(
            select(Task).where(Task.run_id == run.id, Task.kind == "context-bootstrap")
        ).scalar_one()
        codex_task = self.db.execute(
            select(Task).where(Task.run_id == run.id, Task.kind == "orchestrate")
        ).scalar_one()
        action = self.db.execute(select(Action).where(Action.task_id == codex_task.id)).scalar_one()
        action.command = shell_preview
        action.parameters_json = {
            "workspace_dir": str(workspace_dir),
            "model": settings.default_model,
            "reasoning_effort": settings.default_reasoning_effort,
            "codex_bin": codex_bin,
        }
        action.result_json = {
            "prompt_length": len(bundle["assembled_prompt"]),
            "codex_available": runner.is_available(),
        }
        action.output_text = bundle["assembled_prompt"]

        context_task.status = "ready"
        codex_task.status = "ready"

        artifact = Artifact(
            run_id=run.id,
            action_id=action.id,
            kind="context_bundle",
            path=str(run_paths.prompts / "orchestrator_context.txt"),
            metadata_json={
                "mode": run.mode,
                "prompt_prefix": bundle["prompt_prefix"],
            },
        )
        self.db.add(artifact)
