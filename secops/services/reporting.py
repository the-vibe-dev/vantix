from __future__ import annotations

import base64
import csv
import hashlib
import html
import json
import mimetypes
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from secops.models import Artifact, Fact, Finding, RunEvent, WorkspaceRun, WorkflowExecution, WorkflowPhaseRun
from secops.services.storage import StorageLayout


class ReportingService:
    def __init__(self) -> None:
        self.storage = StorageLayout()

    def generate(self, db: Session, run: WorkspaceRun) -> dict:
        paths = self.storage.for_workspace(run.workspace_id)
        facts = db.query(Fact).filter(Fact.run_id == run.id).order_by(Fact.created_at.asc()).all()
        findings = db.query(Finding).filter(Finding.run_id == run.id).order_by(Finding.created_at.asc()).all()
        events = db.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.sequence.asc()).all()
        artifacts = db.query(Artifact).filter(Artifact.run_id == run.id).order_by(Artifact.created_at.asc()).all()
        workflow = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.run_id == run.id)
            .order_by(WorkflowExecution.created_at.desc())
            .first()
        )
        phase_attempts = (
            db.query(WorkflowPhaseRun)
            .filter(WorkflowPhaseRun.run_id == run.id)
            .order_by(WorkflowPhaseRun.created_at.asc())
            .all()
        )

        report_json = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run.id,
            "workspace_id": run.workspace_id,
            "mode": run.mode,
            "target": run.target,
            "objective": run.objective,
            "workflow_id": workflow.id if workflow else "",
            "workflow_status": workflow.status if workflow else run.status,
            "phase_attempts": [
                {
                    "phase": row.phase_name,
                    "attempt": row.attempt,
                    "status": row.status,
                    "retry_class": row.retry_class,
                    "worker_id": row.worker_id,
                }
                for row in phase_attempts
            ],
            "findings": [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "summary": finding.summary,
                    "evidence": finding.evidence,
                    "reproduction": finding.reproduction,
                    "remediation": finding.remediation,
                    "confidence": finding.confidence,
                    "validation": self._validation_metadata_from_text(finding.evidence or ""),
                    "fingerprint": finding.fingerprint,
                    "evidence_ids": list(finding.evidence_ids or []),
                    "reproduction_script": finding.reproduction_script or "",
                    "promoted_at": finding.promoted_at.isoformat() if finding.promoted_at else None,
                    "reviewed_at": finding.reviewed_at.isoformat() if finding.reviewed_at else None,
                    "reviewer_user_id": finding.reviewer_user_id,
                    "disposition": finding.disposition,
                }
                for finding in findings
            ],
            "facts": [{"id": fact.id, "kind": fact.kind, "value": fact.value, "source": fact.source, "confidence": fact.confidence} for fact in facts],
            "artifacts": [{"id": art.id, "kind": art.kind, "path": art.path} for art in artifacts],
            "events": [{"id": ev.id, "sequence": ev.sequence, "type": ev.event_type, "level": ev.level, "message": ev.message} for ev in events[-80:]],
            "negative_evidence": [fact.value for fact in facts if fact.kind in {"negative_evidence", "no_finding"}],
        }
        observation_facts = [fact for fact in facts if fact.kind in {"port", "service", "route", "form", "cve", "intel", "browser-session"}]
        hypothesis_facts = [fact for fact in facts if fact.kind in {"vector", "attack_chain"}]
        validated_findings = [finding for finding in findings if str(finding.status or "").lower() in {"validated", "confirmed", "draft"}]
        browser_artifacts = [
            art
            for art in artifacts
            if art.kind in {"browser-session-summary", "browser-auth-state", "browser-js-signals", "route-discovery", "form-map", "network-summary", "screenshot", "dom-snapshot"}
        ]
        browser_summary: dict[str, Any] = {
            "enabled": bool(browser_artifacts),
            "pages_visited": 0,
            "routes_discovered": 0,
            "forms_discovered": 0,
            "authenticated": "not_attempted",
            "blocked_actions": [],
            "artifact_count": len(browser_artifacts),
            "auth_transitions": [],
            "dom_diffs": [],
            "js_signals": [],
            "route_hints": [],
            "session_summary": {},
        }
        for art in browser_artifacts:
            if art.kind not in {"browser-session-summary", "browser-auth-state", "browser-js-signals", "route-discovery", "form-map"}:
                continue
            try:
                payload = json.loads(Path(art.path).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                continue
            if art.kind == "browser-session-summary":
                browser_summary["pages_visited"] = int(payload.get("pages_visited") or 0)
                browser_summary["authenticated"] = str(payload.get("authenticated") or "not_attempted")
                browser_summary["blocked_actions"] = [str(item) for item in (payload.get("blocked_actions") or [])][:100]
                browser_summary["session_summary"] = payload if isinstance(payload, dict) else {}
            elif art.kind == "browser-auth-state":
                browser_summary["auth_transitions"] = [item for item in (payload.get("auth_transitions") or []) if isinstance(item, dict)][:20]
                browser_summary["dom_diffs"] = [item for item in (payload.get("dom_diffs") or []) if isinstance(item, dict)][:20]
            elif art.kind == "browser-js-signals":
                pages = [item for item in (payload.get("pages") or []) if isinstance(item, dict)][:40]
                signals: list[dict[str, Any]] = []
                hints: list[dict[str, Any]] = []
                for item in pages:
                    url = str(item.get("url") or "")
                    for signal in item.get("js_signals") or []:
                        if isinstance(signal, dict):
                            signals.append({"url": url, **signal})
                    for hint in item.get("route_hints") or []:
                        if str(hint or "").strip():
                            hints.append({"url": url, "hint": str(hint)})
                browser_summary["js_signals"] = signals[:40]
                browser_summary["route_hints"] = hints[:40]
            elif art.kind == "route-discovery":
                edges = payload.get("edges") or []
                routes = {str(item.get("to") or "") for item in edges if isinstance(item, dict) and str(item.get("to") or "")}
                browser_summary["routes_discovered"] = max(browser_summary["routes_discovered"], len(routes))
            elif art.kind == "form-map":
                forms = payload.get("forms") or []
                count = 0
                for item in forms:
                    if isinstance(item, dict):
                        count += len(item.get("forms") or [])
                browser_summary["forms_discovered"] = max(browser_summary["forms_discovered"], count)
        report_json["browser_assessment"] = browser_summary

        port_values = sorted({fact.value for fact in facts if fact.kind == "port"})
        service_values = sorted({fact.value for fact in facts if fact.kind == "service"})
        cve_values = sorted({fact.value for fact in facts if fact.kind == "cve"})
        exec_evidence = [event.message for event in events if event.event_type == "terminal" and event.message.strip()]
        high_conf_findings = [item for item in report_json["findings"] if str(item.get("status", "")).lower() in {"validated", "confirmed", "draft"}]
        executive_summary = (
            f"Assessment completed for {run.target or 'unknown target'}. "
            f"Discovered {len(port_values)} open ports and {len(service_values)} service fingerprints. "
            f"Validated findings: {len(validated_findings)}. CVE references: {len(cve_values)}."
        )

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        finding_rows = sorted(
            report_json["findings"],
            key=lambda item: (
                severity_order.get(str(item.get("severity") or "").lower(), 5),
                -float(item.get("confidence") or 0.0),
                str(item.get("title") or "").lower(),
            ),
        )
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for item in finding_rows:
            sev = str(item.get("severity") or "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["info"] += 1

        screenshots = [art.path for art in artifacts if art.kind == "screenshot" and str(art.path).strip()]
        md_lines = [
            f"# Technical Security Assessment: {run.target or run.workspace_id}",
            "",
            "## Executive Summary",
            executive_summary,
            "",
            "## Scope",
            f"- Run ID: `{run.id}`",
            f"- Mode: `{run.mode}`",
            f"- Target: `{run.target}`",
            f"- Objective: {run.objective}",
            "",
            "## Attack Surface",
            f"- Open TCP ports: {', '.join(port_values) if port_values else 'none observed'}",
            f"- Services: {', '.join(service_values) if service_values else 'none observed'}",
            f"- CVE references observed: {', '.join(cve_values[:20]) if cve_values else 'none observed'}",
            "",
            "## Findings Summary",
            f"- Critical: {severity_counts['critical']}",
            f"- High: {severity_counts['high']}",
            f"- Medium: {severity_counts['medium']}",
            f"- Low: {severity_counts['low']}",
            f"- Informational: {severity_counts['info']}",
            "",
            "## Technical Findings",
        ]
        if finding_rows:
            for idx, item in enumerate(finding_rows, start=1):
                clean_evidence = self._strip_artifact_suffix(str(item.get("evidence") or "(not provided)"))
                inline_artifacts = self._extract_artifact_paths(f"{item.get('evidence') or ''}\n{item.get('reproduction') or ''}")
                validation_meta = dict(item.get("validation") or self._validation_metadata_from_text(str(item.get("evidence") or "")))
                md_lines.extend(
                    [
                        f"### {idx}. {item['title']}",
                        f"- Severity: {str(item.get('severity') or 'info').upper()}",
                        f"- Status: {item.get('status') or 'validated'}",
                        f"- Confidence: {float(item.get('confidence') or 0.0):.2f}",
                        f"- Disposition: {item.get('disposition') or 'draft'}",
                        f"- Promoted: {item.get('promoted_at') or 'not recorded'}",
                        f"- Reviewed: {item.get('reviewed_at') or 'pending'}"
                        + (f" by user {item.get('reviewer_user_id')}" if item.get("reviewer_user_id") else ""),
                        f"- Risk Tags: {validation_meta.get('risk_tags') or 'none'}",
                        f"- Attempted: {validation_meta.get('attempted') or 'unknown'}",
                        f"- Impact Bound: {validation_meta.get('impact_bound') or 'not recorded'}",
                        f"- State Changed: {validation_meta.get('state_changed') or 'unknown'}",
                        f"- Cleanup Attempted: {validation_meta.get('cleanup_attempted') or 'unknown'}",
                        f"- Vector Explanation: {item.get('summary') or '(not provided)'}",
                        "",
                        "**Proof Of Concept**",
                        (item.get("reproduction") or "(not provided)"),
                        "",
                        "**Evidence**",
                        clean_evidence,
                        "",
                        "**Remediation**",
                        (item.get("remediation") or "(not provided)"),
                        "",
                    ]
                )
                if item.get("reproduction_script"):
                    md_lines.extend(
                        [
                            "**Reproduction Script**",
                            "```bash",
                            str(item["reproduction_script"]).rstrip(),
                            "```",
                            "",
                        ]
                    )
                if item.get("evidence_ids"):
                    md_lines.append("**Linked Evidence**")
                    for eid in item["evidence_ids"]:
                        md_lines.append(f"- [{eid}](artifacts/{eid})")
                    md_lines.append("")
                if inline_artifacts:
                    md_lines.append("**Artifact Review**")
                    for art_path in inline_artifacts:
                        p = Path(art_path)
                        md_lines.append(f"- evidence: {art_path}")
                        if not p.exists() or not p.is_file():
                            md_lines.append("  - Artifact missing on disk.")
                            continue
                        if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}:
                            md_lines.append(f"  ![{p.name}]({art_path})")
                            continue
                        payload = self._read_text_artifact(p)
                        if payload is None:
                            md_lines.append("  - Binary artifact (non-text).")
                            continue
                        md_lines.append("")
                        md_lines.append("```text")
                        md_lines.append(payload.rstrip("\n"))
                        md_lines.append("```")
                        md_lines.append("")
        else:
            md_lines.append("- No findings were recorded for this run.")

        if screenshots:
            md_lines.extend(["## Browser Evidence Images"])
            for img in screenshots[:24]:
                md_lines.append(f"- {img}")
                md_lines.append(f"![Screenshot]({img})")
            md_lines.append("")

        if exec_evidence:
            md_lines.extend(["## Validation Notes"])
            for line in exec_evidence[:40]:
                md_lines.append(f"- {line}")
            md_lines.append("")

        md_lines.extend(
            [
                "## Recommendations",
                "- Prioritize critical and high findings first, then re-run focused validation.",
                "- Add automated regression checks for every validated PoC path.",
                "- Keep this report as the baseline and compare deltas on retest.",
            ]
        )

        md_path = paths.artifacts / "run_report.md"
        html_path = paths.artifacts / "run_report.html"
        report_json["executive_summary"] = executive_summary
        paths.write_text(Path(md_path), "\n".join(md_lines) + "\n")
        paths.write_text(
            Path(html_path),
            self._render_human_html(
                run=run,
                executive_summary=executive_summary,
                port_values=port_values,
                service_values=service_values,
                severity_counts=severity_counts,
                findings=finding_rows,
                screenshots=screenshots,
            ),
        )

        provenance_path = self._emit_provenance_manifest(
            paths=paths, run=run, findings=findings, artifacts=artifacts
        )
        attestation_path = self._emit_attestation(
            paths=paths, run=run, report_paths=[md_path, html_path, provenance_path]
        )

        return {
            "markdown_path": str(md_path),
            "html_path": str(html_path),
            "json_path": "",
            "comprehensive_markdown_path": "",
            "comprehensive_json_path": "",
            "artifact_index_path": "",
            "timeline_csv_path": "",
            "provenance_path": str(provenance_path),
            "attestation_path": str(attestation_path),
            "summary": report_json,
        }

    def _emit_provenance_manifest(
        self,
        *,
        paths,
        run: WorkspaceRun,
        findings: list[Finding],
        artifacts: list[Artifact],
    ) -> Path:
        """P4-1 — Per-finding provenance manifest.

        Captures the chain-of-custody trio, fingerprint, evidence linkage,
        and a sha256 over the reproduction script so downstream consumers
        can verify each finding without trusting the Markdown/HTML render.
        """
        artifact_sha: dict[str, str] = {}
        for artifact in artifacts:
            artifact_path = Path(artifact.path)
            if artifact_path.is_file():
                try:
                    artifact_sha[artifact.id] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                except OSError:
                    continue

        rows: list[dict[str, Any]] = []
        for finding in findings:
            evidence_ids = list(finding.evidence_ids or [])
            repro = finding.reproduction_script or ""
            rows.append(
                {
                    "id": finding.id,
                    "fingerprint": finding.fingerprint or "",
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "disposition": finding.disposition or "draft",
                    "confidence": float(finding.confidence or 0.0),
                    "promoted_at": finding.promoted_at.isoformat() if finding.promoted_at else None,
                    "reviewed_at": finding.reviewed_at.isoformat() if finding.reviewed_at else None,
                    "reviewer_user_id": finding.reviewer_user_id or None,
                    "evidence_ids": evidence_ids,
                    "evidence_sha256": {eid: artifact_sha[eid] for eid in evidence_ids if eid in artifact_sha},
                    "reproduction_script_sha256": hashlib.sha256(repro.encode("utf-8")).hexdigest() if repro else "",
                }
            )

        manifest = {
            "schema_version": 1,
            "kind": "vantix.finding_provenance.v1",
            "run_id": run.id,
            "engagement_id": run.engagement_id,
            "workspace_id": run.workspace_id,
            "target": run.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "finding_count": len(rows),
            "findings": rows,
        }
        out_path = paths.artifacts / "findings.provenance.json"
        paths.write_text(Path(out_path), json.dumps(manifest, indent=2, sort_keys=True))
        return out_path

    def _emit_attestation(
        self,
        *,
        paths,
        run: WorkspaceRun,
        report_paths: list[Path],
    ) -> Path:
        """P4-3 — Signable attestation envelope over the rendered reports.

        Writes a manifest of report artifacts with sha256 digests suitable
        for ``cosign sign-blob`` (see ``scripts/sign-report.sh``). The
        attestation file itself is what gets signed; verifiers recompute
        the listed hashes against the rendered files to validate both the
        signature and the bundle integrity.
        """
        entries: list[dict[str, Any]] = []
        for report_path in report_paths:
            rp = Path(report_path)
            if not rp.is_file():
                continue
            data = rp.read_bytes()
            entries.append(
                {
                    "path": rp.name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data),
                }
            )
        envelope = {
            "schema_version": 1,
            "kind": "vantix.report_attestation.v1",
            "run_id": run.id,
            "workspace_id": run.workspace_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "reports": entries,
        }
        out_path = paths.artifacts / "report.attestation.json"
        paths.write_text(Path(out_path), json.dumps(envelope, indent=2, sort_keys=True))
        return out_path

    def _render_human_html(
        self,
        *,
        run: WorkspaceRun,
        executive_summary: str,
        port_values: list[str],
        service_values: list[str],
        severity_counts: dict[str, int],
        findings: list[dict[str, Any]],
        screenshots: list[str],
    ) -> str:
        def esc(value: Any) -> str:
            return html.escape(str(value or ""))

        chips = "".join(
            f"<span class='chip {sev}'>{sev.upper()}: {severity_counts.get(sev, 0)}</span>"
            for sev in ("critical", "high", "medium", "low", "info")
        )
        finding_cards: list[str] = []
        for idx, item in enumerate(findings, start=1):
            sev = str(item.get("severity") or "info").lower()
            clean_evidence = self._strip_artifact_suffix(str(item.get("evidence") or "(not provided)"))
            inline_artifacts = self._extract_artifact_paths(f"{item.get('evidence') or ''}\n{item.get('reproduction') or ''}")
            validation_meta = dict(item.get("validation") or self._validation_metadata_from_text(str(item.get("evidence") or "")))
            validation_html = self._render_validation_meta_html(validation_meta)
            artifact_blocks = []
            for path in inline_artifacts:
                artifact_blocks.append(self._render_artifact_html_block(path, kind_hint="evidence"))
            artifact_html = ""
            if artifact_blocks:
                artifact_html = f"<h4>Artifact Review</h4>{''.join(artifact_blocks)}"
            finding_cards.append(
                (
                    "<article class='finding'>"
                    f"<h3>{idx}. {esc(item.get('title'))}</h3>"
                    f"<div class='meta'><span class='badge {esc(sev)}'>{esc(sev.upper())}</span>"
                    f"<span>Status: {esc(item.get('status') or 'validated')}</span>"
                    f"<span>Confidence: {float(item.get('confidence') or 0.0):.2f}</span></div>"
                    f"{validation_html}"
                    f"<h4>Vector Explanation</h4><p>{esc(item.get('summary') or '(not provided)')}</p>"
                    f"<h4>PoC</h4><pre>{esc(item.get('reproduction') or '(not provided)')}</pre>"
                    f"<h4>Evidence</h4><pre>{esc(clean_evidence)}</pre>"
                    f"<h4>Remediation</h4><p>{esc(item.get('remediation') or '(not provided)')}</p>"
                    f"{artifact_html}"
                    "</article>"
                )
            )
        if not finding_cards:
            finding_cards.append("<p>No findings were recorded for this run.</p>")

        image_blocks = "".join(self._render_artifact_html_block(path, kind_hint="screenshot") for path in screenshots[:24])
        if not image_blocks:
            image_blocks = "<p>No screenshots were captured.</p>"
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>Security Report - {esc(run.target or run.workspace_id)}</title>"
            "<style>"
            "body{font-family:Inter,Arial,sans-serif;background:#f5f7fb;color:#1a1f2b;margin:0;padding:0;line-height:1.45}"
            ".wrap{max-width:1100px;margin:0 auto;padding:24px}"
            "h1,h2,h3,h4{margin:0 0 10px 0}"
            "section{background:#fff;border:1px solid #d9e0ee;border-radius:8px;padding:18px;margin:0 0 16px 0}"
            ".chip,.badge{display:inline-block;padding:4px 8px;border-radius:6px;font-size:12px;font-weight:600;border:1px solid #cdd6e6;margin-right:6px}"
            ".critical{background:#fee2e2}.high{background:#ffedd5}.medium{background:#fef9c3}.low{background:#dcfce7}.info{background:#e0f2fe}"
            ".finding{border-top:1px solid #e7ecf6;padding-top:14px;margin-top:14px}"
            ".meta{display:flex;gap:10px;flex-wrap:wrap;margin:6px 0 10px 0;font-size:13px}"
            ".validation{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin:8px 0 12px 0}"
            ".validation div{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:8px;font-size:12px}"
            "pre{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:12px;overflow:auto;font-size:12px;white-space:pre-wrap}"
            "figure{margin:0 0 14px 0} img{max-width:100%;height:auto;border:1px solid #d9e0ee;border-radius:6px}"
            "figcaption{font-size:12px;color:#475569;margin-top:4px;word-break:break-all}"
            "details{margin:8px 0 12px 0} summary{cursor:pointer;font-weight:600;color:#0f172a}"
            ".muted{color:#475569;font-size:14px}"
            "</style></head><body>"
            "<div class='wrap'>"
            f"<section><h1>Security Assessment Report</h1><p class='muted'>Target: {esc(run.target)} | Run: {esc(run.id)}</p>"
            f"<p>{esc(executive_summary)}</p><div>{chips}</div></section>"
            "<section><h2>Attack Surface</h2>"
            f"<p><strong>Open Ports:</strong> {esc(', '.join(port_values) if port_values else 'none observed')}</p>"
            f"<p><strong>Services:</strong> {esc(', '.join(service_values) if service_values else 'none observed')}</p>"
            "</section>"
            f"<section><h2>Findings And PoC</h2>{''.join(finding_cards)}</section>"
            f"<section><h2>Evidence Images</h2>{image_blocks}</section>"
            "</div></body></html>"
        )

    def _extract_artifact_paths(self, text: str) -> list[str]:
        raw = str(text or "")
        if not raw:
            return []
        found = re.findall(r"(/[A-Za-z0-9._~:/%+\\-]+)", raw)
        paths: list[str] = []
        seen: set[str] = set()
        for token in found:
            cleaned = token.rstrip(".,);]'\"")
            p = Path(cleaned)
            if not p.is_absolute():
                continue
            if not p.exists():
                continue
            key = str(p)
            if key in seen:
                continue
            seen.add(key)
            paths.append(key)
        return paths

    def _render_artifact_html_block(self, path: str, *, kind_hint: str = "artifact") -> str:
        p = Path(str(path or ""))
        label = f"{kind_hint}: {p}"
        if not p.exists() or not p.is_file():
            return (
                "<details>"
                f"<summary>{html.escape(label)} (missing)</summary>"
                f"<pre>{html.escape(str(p))}</pre>"
                "</details>"
            )
        suffix = p.suffix.lower()
        if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}:
            data_uri = self._image_data_uri(p)
            if data_uri:
                return (
                    "<details>"
                    f"<summary>{html.escape(label)} (image)</summary>"
                    "<figure>"
                    f"<img src='{data_uri}' alt='{html.escape(p.name)}'>"
                    f"<figcaption>{html.escape(str(p))}</figcaption>"
                    "</figure>"
                    "</details>"
                )
        text_payload = self._read_text_artifact(p)
        if text_payload is None:
            return (
                "<details>"
                f"<summary>{html.escape(label)} (binary)</summary>"
                f"<pre>{html.escape(str(p))}</pre>"
                "</details>"
            )
        return "<details>" f"<summary>{html.escape(label)}</summary>" f"<pre>{html.escape(text_payload)}</pre>" "</details>"

    def _image_data_uri(self, path: Path) -> str:
        try:
            raw = path.read_bytes()
        except OSError:
            return ""
        mime, _ = mimetypes.guess_type(str(path))
        if not mime:
            mime = "image/png"
        encoded = base64.b64encode(raw).decode("ascii")
        return f"data:{mime};base64,{encoded}"

    def _read_text_artifact(self, path: Path) -> str | None:
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return raw.decode("latin-1")
            except UnicodeDecodeError:
                return None

    def _strip_artifact_suffix(self, text: str) -> str:
        value = str(text or "")
        if "Validation Metadata:" in value:
            value = value.split("Validation Metadata:", 1)[0]
        cleaned = re.sub(r"\s*Artifact:\s*/\S+", "", value).strip()
        return cleaned or value.strip()

    def _validation_metadata_from_text(self, text: str) -> dict[str, str]:
        raw = str(text or "")
        if "Validation Metadata:" not in raw:
            return {}
        metadata: dict[str, str] = {}
        _, tail = raw.split("Validation Metadata:", 1)
        for line in tail.splitlines():
            stripped = line.strip()
            if not stripped.startswith("- ") or ":" not in stripped:
                continue
            key, value = stripped[2:].split(":", 1)
            normalized = re.sub(r"[^a-z0-9]+", "_", key.strip().lower()).strip("_")
            if normalized:
                metadata[normalized] = value.strip()
        return metadata

    def _render_validation_meta_html(self, metadata: dict[str, str]) -> str:
        if not metadata:
            return ""
        labels = [
            ("risk_tags", "Risk Tags"),
            ("attempted", "Attempted"),
            ("impact_bound", "Impact Bound"),
            ("state_changed", "State Changed"),
            ("cleanup_attempted", "Cleanup Attempted"),
            ("why_not_attempted", "Why Not Attempted"),
        ]
        blocks = []
        for key, label in labels:
            value = str(metadata.get(key) or "").strip()
            if not value:
                continue
            blocks.append(f"<div><strong>{html.escape(label)}</strong><br>{html.escape(value)}</div>")
        return f"<div class='validation'>{''.join(blocks)}</div>" if blocks else ""

    def _build_artifact_index(self, run_id: str, artifacts: list[Artifact]) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": [
                {
                    "id": art.id,
                    "kind": art.kind,
                    "path": art.path,
                    "created_at": art.created_at.isoformat() if art.created_at else "",
                    "metadata": dict(art.metadata_json or {}),
                }
                for art in artifacts
            ],
        }

    def _render_artifact_index_markdown(self, payload: dict[str, Any]) -> str:
        lines = [
            f"# Artifact Index: {payload.get('run_id', '')}",
            "",
            f"- Generated at: {payload.get('generated_at', '')}",
            f"- Total artifacts: {len(payload.get('artifacts') or [])}",
            "",
            "| kind | path | artifact_id |",
            "|---|---|---|",
        ]
        for row in payload.get("artifacts") or []:
            lines.append(f"| {row.get('kind','')} | {row.get('path','')} | {row.get('id','')} |")
        return "\n".join(lines) + "\n"

    def _write_timeline_csv(self, path: Path, events: list[RunEvent]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["sequence", "event_type", "level", "message", "created_at"],
            )
            writer.writeheader()
            for ev in events:
                writer.writerow(
                    {
                        "sequence": ev.sequence,
                        "event_type": ev.event_type,
                        "level": ev.level,
                        "message": ev.message,
                        "created_at": ev.created_at.isoformat() if ev.created_at else "",
                    }
                )

    def _build_comprehensive_payload(
        self,
        *,
        run: WorkspaceRun,
        facts: list[Fact],
        findings: list[Finding],
        events: list[RunEvent],
        artifacts: list[Artifact],
        executive_summary: str,
        port_values: list[str],
        service_values: list[str],
    ) -> dict[str, Any]:
        categories = [
            ("authentication", "Authentication Vulnerabilities"),
            ("authorization", "Authorization Vulnerabilities"),
            ("xss", "Cross-Site Scripting (XSS) Vulnerabilities"),
            ("injection", "SQL/Command Injection Vulnerabilities"),
            ("ssrf", "Server-Side Request Forgery (SSRF) Vulnerabilities"),
            ("exposure", "Sensitive Exposure & Security Misconfiguration"),
            ("network", "Network Service Exposure"),
        ]
        category_summary: dict[str, Any] = {}
        grouped_findings: dict[str, list[Finding]] = {key: [] for key, _ in categories}
        for item in findings:
            grouped_findings[self._finding_category(item)].append(item)
        for key, label in categories:
            rows = grouped_findings.get(key) or []
            category_summary[key] = {
                "label": label,
                "status": "findings_validated" if rows else "no_validated_findings",
                "count": len(rows),
                "summary": (
                    f"{len(rows)} validated finding(s) recorded in this category."
                    if rows
                    else "No validated findings were recorded in this category during this run."
                ),
            }

        exploitation = []
        for item in findings:
            exploitation.append(
                {
                    "id": item.id,
                    "title": item.title,
                    "severity": item.severity,
                    "status": item.status,
                    "category": self._finding_category(item),
                    "location": self._extract_location(item),
                    "overview": item.summary or "",
                    "impact": item.evidence or "",
                    "prerequisites": self._extract_prerequisites(item),
                    "steps": self._extract_steps(item),
                    "proof_of_impact": item.evidence or "",
                    "remediation": item.remediation or "",
                }
            )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run.id,
            "workspace_id": run.workspace_id,
            "target": run.target,
            "mode": run.mode,
            "objective": run.objective,
            "executive_summary": executive_summary,
            "vulnerability_type_summary": category_summary,
            "network_reconnaissance": {
                "open_ports": port_values,
                "services": service_values,
                "fact_count": len(facts),
            },
            "exploitation_evidence": exploitation,
            "findings": [
                {
                    "id": item.id,
                    "title": item.title,
                    "severity": item.severity,
                    "status": item.status,
                    "summary": item.summary,
                    "evidence": item.evidence,
                    "reproduction": item.reproduction,
                    "remediation": item.remediation,
                    "confidence": item.confidence,
                }
                for item in findings
            ],
            "artifacts": [
                {"id": art.id, "kind": art.kind, "path": art.path, "metadata": dict(art.metadata_json or {})}
                for art in artifacts
            ],
            "timeline": [
                {
                    "sequence": ev.sequence,
                    "event_type": ev.event_type,
                    "level": ev.level,
                    "message": ev.message,
                    "created_at": ev.created_at.isoformat() if ev.created_at else "",
                }
                for ev in events
            ],
        }

    def _finding_category(self, finding: Finding) -> str:
        text = " ".join(
            [
                str(finding.title or ""),
                str(finding.summary or ""),
                str(finding.evidence or ""),
            ]
        ).lower()
        if any(token in text for token in ["ssrf", "server-side request forgery"]):
            return "ssrf"
        if any(token in text for token in ["xss", "cross-site", "jsonp", "callback execution"]):
            return "xss"
        if any(token in text for token in ["sql injection", "command injection", "nosql", "xxe", "yaml", "injection bypass", "database error"]):
            return "injection"
        if any(token in text for token in ["rpcbind", "portmapper", "jetdirect", "raw print", "tcp/9100", "ssh"]):
            return "network"
        if any(token in text for token in ["admin configuration", "/rest/admin/application-configuration", "sensitive endpoint"]):
            return "authorization"
        if any(token in text for token in ["metrics", "version", "cors", "content-security-policy", "swagger", "api documentation", "telemetry", "header"]):
            return "exposure"
        if any(token in text for token in ["idor", "authorization", "access control", "privilege", "unauthenticated", "object-level", "admin configuration", "sensitive endpoint"]):
            return "authorization"
        if any(token in text for token in ["login", "jwt", "session", "password", "token replay", "brute force", "credential"]):
            return "authentication"
        return "exposure"

    def _extract_location(self, finding: Finding) -> str:
        text = " ".join([str(finding.evidence or ""), str(finding.summary or "")]).strip()
        if not text:
            return ""
        return text.splitlines()[0][:240]

    def _extract_prerequisites(self, finding: Finding) -> list[str]:
        base = []
        reproduction = str(finding.reproduction or "").lower()
        evidence = str(finding.evidence or "").lower()
        if "without authentication" in reproduction or "unauthenticated" in evidence:
            return ["None beyond network reachability to target scope"]
        if reproduction:
            if "token" in reproduction:
                base.append("Valid authentication token")
            if "admin" in reproduction:
                base.append("Elevated role/session where noted in reproduction")
        if not base:
            base.append("None beyond network reachability to target scope")
        return base

    def _extract_steps(self, finding: Finding) -> list[str]:
        if finding.reproduction:
            lines = [line.strip() for line in finding.reproduction.splitlines() if line.strip()]
            return lines[:20]
        if finding.evidence:
            return [finding.evidence]
        return ["Reproduction details not provided in finding record."]

    def _render_comprehensive_markdown(self, payload: dict[str, Any]) -> str:
        lines: list[str] = []
        lines.append("# Security Assessment Report")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(f"- **Target:** {payload.get('target') or '(unknown)'}")
        lines.append(f"- **Assessment Date:** {str(payload.get('generated_at') or '')[:10]}")
        lines.append("- **Scope:** Authentication, XSS, SQL and Command Injection, SSRF, Authorization testing")
        lines.append("")
        lines.append("## Summary by Vulnerability Type")
        lines.append("")
        for key in ["authentication", "authorization", "xss", "injection", "ssrf", "exposure", "network"]:
            row = (payload.get("vulnerability_type_summary") or {}).get(key) or {}
            lines.append(f"### {row.get('label', key)}")
            lines.append(f"**Status:** {row.get('summary', '')}")
            lines.append("")
        lines.append("## Network Reconnaissance")
        recon = payload.get("network_reconnaissance") or {}
        ports = recon.get("open_ports") or []
        services = recon.get("services") or []
        lines.append(f"- Open Ports: {', '.join(ports) if ports else 'None recorded'}")
        lines.append(f"- Services: {', '.join(services) if services else 'None recorded'}")
        lines.append("")
        lines.append("## Exploitation Evidence")
        evidence = payload.get("exploitation_evidence") or []
        if not evidence:
            lines.append("")
            lines.append("No validated exploitation evidence was recorded for this run.")
        for row in evidence:
            lines.append("")
            lines.append(f"### {row.get('title','(untitled)')}")
            lines.append("")
            lines.append(f"- **Severity:** {row.get('severity','')}")
            lines.append(f"- **Category:** {row.get('category','')}")
            lines.append(f"- **Location:** {row.get('location','') or '(not provided)'}")
            lines.append(f"- **Overview:** {row.get('overview','') or '(not provided)'}")
            lines.append(f"- **Impact:** {row.get('impact','') or '(not provided)'}")
            lines.append("")
            lines.append("**Prerequisites:**")
            for item in row.get("prerequisites") or []:
                lines.append(f"- {item}")
            lines.append("")
            lines.append("**Exploitation Steps:**")
            for idx, step in enumerate(row.get("steps") or [], start=1):
                lines.append(f"{idx}. {step}")
            lines.append("")
            lines.append("**Proof of Impact:**")
            lines.append(row.get("proof_of_impact", "") or "(not provided)")
            lines.append("")
            lines.append("**Remediation:**")
            lines.append(row.get("remediation", "") or "(not provided)")
        lines.append("")
        lines.append("## Evidence Artifacts")
        for art in payload.get("artifacts") or []:
            lines.append(f"- {art.get('kind','')}: {art.get('path','')}")
        lines.append("")
        lines.append("## Timeline")
        for row in (payload.get("timeline") or [])[:200]:
            lines.append(f"- #{row.get('sequence','')} [{row.get('event_type','')}] {row.get('message','')}")
        return "\n".join(lines) + "\n"
