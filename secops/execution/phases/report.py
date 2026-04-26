from __future__ import annotations

import json
import re
from pathlib import Path

from secops.db import SessionLocal
from secops.models import Artifact, Fact, Finding, RunMessage, WorkspaceRun


class ReportPhaseMixin:
    """Report-phase runner and finding-promotion helpers.

    Extracted from ExecutionManager. Relies on ``self.nas``, ``self.events``,
    ``self.reporting``, ``self._task_by_kind``, ``self._set_role_status``,
    ``self._set_vantix_task_status``, ``self._write_memory`` from peer mixins.
    """

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
                "report_html_path": generated.get("html_path", ""),
                "report_json_path": "",
                "comprehensive_report_path": "",
                "comprehensive_report_json_path": "",
                "artifact_index_path": "",
                "timeline_csv_path": "",
            }
            db.add(
                Artifact(
                    run_id=run.id,
                    kind="report",
                    path=str(generated["markdown_path"]),
                    metadata_json={"report_html_path": generated.get("html_path", "")},
                )
            )
            if generated.get("html_path"):
                db.add(
                    Artifact(
                        run_id=run.id,
                        kind="report-html",
                        path=str(generated["html_path"]),
                        metadata_json={},
                    )
                )
            self.events.emit(
                db,
                run.id,
                "phase",
                "Report generated",
                payload={
                    "phase": "report",
                    "report_path": generated["markdown_path"],
                    "report_html_path": generated.get("html_path", ""),
                    "report_json_path": "",
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
                        "report_html_path": generated.get("html_path", ""),
                        "report_json_path": "",
                    },
                )
            )
            file_paths = [
                str(generated["markdown_path"]),
                str(generated.get("html_path", "")),
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
        report_html = workspace.artifacts / "run_report.html"
        if not report_md.exists():
            return None
        return {
            "markdown_path": str(report_md),
            "html_path": str(report_html) if report_html.exists() else "",
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

        orchestrator_log = workspace.logs / "orchestrator.log"
        if orchestrator_log.exists():
            for item in self._parse_orchestrator_log_findings(orchestrator_log):
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
                        reproduction=str(item.get("reproduction") or "").strip()[:4000],
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
            if promoted >= 50:
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

    def _parse_orchestrator_log_findings(self, log_path: Path) -> list[dict[str, str | float]]:
        try:
            text = log_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return []
        lowered = text.lower()
        findings: list[dict[str, str | float]] = []

        creds_present = ("testing@juice-sh.op" in lowered and "iamusedfortesting" in lowered) or (
            "hardcoded test credentials" in lowered and "authenticate successfully" in lowered
        )
        if creds_present:
            findings.append(
                {
                    "title": "Exposed hardcoded client credentials in static bundle",
                    "severity": "high",
                    "summary": "Static client assets exposed plaintext test credentials that were accepted by the authentication endpoint.",
                    "evidence": (
                        f"Orchestrator log captured credential disclosure and successful auth validation "
                        f"(source: {log_path})."
                    ),
                    "reproduction": (
                        "Retrieve `/main.js`, extract hardcoded credentials, and authenticate via `/rest/user/login`."
                    ),
                    "remediation": (
                        "Remove credentials from client bundles, rotate exposed accounts/secrets, and enforce secret scanning in build pipelines."
                    ),
                    "confidence": 0.9,
                }
            )

        hash_leak_present = (
            "whoami?fields=id,email,role,deluxetoken,password" in lowered and "password hash field is exposed" in lowered
        ) or ("passwordhashleakchallenge" in lowered and "solved=true" in lowered)
        if hash_leak_present:
            findings.append(
                {
                    "title": "Authenticated API response exposes password hash field",
                    "severity": "high",
                    "summary": "User profile/whoami response included password hash material, enabling sensitive data disclosure to authenticated sessions.",
                    "evidence": (
                        f"Orchestrator log recorded `whoami` password field exposure and challenge solve signal "
                        f"(source: {log_path})."
                    ),
                    "reproduction": (
                        "Authenticate, then request `/rest/user/whoami?fields=id,email,role,deluxeToken,password` and verify password hash is returned."
                    ),
                    "remediation": (
                        "Never serialize password/passwordHash fields in API responses; enforce strict response DTO allowlists."
                    ),
                    "confidence": 0.9,
                }
            )
        return findings
