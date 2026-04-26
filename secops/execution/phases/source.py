from __future__ import annotations

import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secops.config import settings
from secops.db import SessionLocal
from secops.models import Artifact, Fact, WorkspaceRun


class SourceAnalysisPhaseMixin:
    """Source-intake-driven white-box analysis phase.

    Extracted from ExecutionManager. Relies on ``self.nas``, ``self.events``,
    ``self._task_by_kind``, ``self._create_agent_session``, ``self._set_role_status``,
    ``self._emit_terminal_excerpt``, ``self._write_memory`` from peer mixins.
    """

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
                report_path = self._stage_source_audit_report(paths, report_path)
                db.add(Artifact(run_id=run.id, kind="source-audit-report", path=report_path, metadata_json={"source_context": source_ctx}))
                ingested = self._ingest_source_audit_report(db, run, report_path, source_ctx)
                task.result_json["source_candidates"] = ingested
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

    def _stage_source_audit_report(self, paths: Any, report_path: str) -> str:
        source = Path(report_path)
        if not source.is_file():
            return report_path
        try:
            source.relative_to(paths.artifacts)
            return str(source)
        except ValueError:
            pass
        dest = paths.artifacts / "source-audit" / source.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
        return str(dest)

    def _ingest_source_audit_report(self, db: Any, run: WorkspaceRun, report_path: str, source_ctx: dict[str, Any]) -> int:
        path = Path(report_path)
        if not path.is_file():
            return 0
        text = path.read_text(encoding="utf-8", errors="ignore")
        source_root = Path(str(source_ctx.get("resolved_path") or ""))
        current: dict[str, str] | None = None
        count = 0
        max_candidates = 60
        section_re = re.compile(r"^### \[(?P<severity>[A-Z]+)\] (?P<name>.+?) \((?P<cwe>CWE-\d+)\)\s*$")
        detail_re = re.compile(r"^(?P<path>/[^:\n]+):(?P<line>\d+):(?P<snippet>.*)$")
        for raw in text.splitlines():
            section = section_re.match(raw.strip())
            if section:
                current = section.groupdict()
                continue
            if not current:
                continue
            detail = detail_re.match(raw.rstrip())
            if not detail:
                continue
            source_file = detail.group("path")
            rel_file = source_file
            if source_root:
                try:
                    rel_file = Path(source_file).resolve().relative_to(source_root.resolve()).as_posix()
                except (OSError, ValueError):
                    rel_file = source_file
            line = detail.group("line")
            snippet = detail.group("snippet").strip()
            severity = current["severity"].lower()
            confidence = {"critical": 0.9, "high": 0.82, "medium": 0.68, "low": 0.45}.get(severity, 0.6)
            title = f"{current['name']}: {rel_file}:{line}"
            metadata = {
                "artifact_path": report_path,
                "source_file": source_file,
                "relative_source_file": rel_file,
                "line": int(line),
                "snippet": snippet[:1000],
                "finding": current["name"],
                "cwe": current["cwe"],
                "severity": current["severity"],
                "source_context": source_ctx,
            }
            db.add(
                Fact(
                    run_id=run.id,
                    source="source-analysis",
                    kind="source-candidate",
                    value=title,
                    confidence=confidence,
                    tags=["source", "white-box", severity, current["cwe"].lower()],
                    metadata_json=metadata,
                )
            )
            count += 1
            if count >= max_candidates:
                break
        db.add(
            Fact(
                run_id=run.id,
                source="source-analysis",
                kind="source-analysis-summary",
                value=f"Source audit produced {count} structured candidate(s)",
                confidence=0.8 if count else 0.2,
                tags=["source", "white-box"],
                metadata_json={"artifact_path": report_path, "source_context": source_ctx, "candidate_count": count},
            )
        )
        return count
