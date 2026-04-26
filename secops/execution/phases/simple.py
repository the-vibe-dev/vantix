from __future__ import annotations

from secops.db import SessionLocal
from secops.mode_profiles import get_mode_profile
from secops.models import Artifact, WorkspaceRun
from secops.services.context_builder import ContextBuilder


class SimplePhasesMixin:
    """Small phase runners: context, learning, source-intake, orchestrate, learn-ingest.

    Extracted from ExecutionManager. Relies on ``self.nas``, ``self.learning``,
    ``self.source_intake``, ``self.events``, ``self._task_by_kind``,
    ``self._set_vantix_task_status``, ``self._set_role_status``,
    ``self._validation_config``, ``self._write_memory`` from peer mixins / __init__.
    """

    def _phase_context(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "context-bootstrap")
            if task.status == "completed":
                return
            paths = self.nas.for_workspace(run.workspace_id)
            cfg = dict(run.config_json or {})
            cfg["validation"] = self._validation_config(run)
            run.config_json = cfg
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

    def _phase_orchestrate(self, run_id: str) -> None:
        from secops.orchestration.orchestrate_phase import run_orchestrate_phase
        run_orchestrate_phase(self, run_id)

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
