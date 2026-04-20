from __future__ import annotations

import csv
import json
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

        md_lines = [
            f"# Run Report: {run.workspace_id}",
            "",
            "## Executive Summary",
            executive_summary,
            "",
            "## Engagement Overview",
            f"- Run ID: {run.id}",
            f"- Mode: {run.mode}",
            f"- Target: {run.target}",
            f"- Objective: {run.objective}",
            f"- Workflow: {report_json['workflow_id'] or '(none)'}",
            f"- Workflow status: {report_json['workflow_status']}",
            "",
            "## Scope And Method",
            "- Scope: single-target assessment based on operator objective.",
            "- Method: phased recon, intelligence correlation, orchestrated validation, and evidence-backed reporting.",
            "",
            "## Attack Surface",
            f"- Open TCP ports: {', '.join(port_values) if port_values else 'none observed'}",
            f"- Service fingerprints: {', '.join(service_values) if service_values else 'none observed'}",
            f"- CVE references: {', '.join(cve_values[:20]) if cve_values else 'none observed'}",
            f"- Observation facts: {len(observation_facts)}",
            f"- Hypothesis vectors/chains: {len(hypothesis_facts)}",
            f"- Validated findings: {len(validated_findings)}",
            "",
            "## Phase Timeline",
        ]
        for phase in report_json["phase_attempts"]:
            md_lines.append(
                f"- {phase['phase']} attempt={phase['attempt']} status={phase['status']} retry={phase['retry_class']} worker={phase['worker_id'] or 'n/a'}"
            )
        md_lines.extend(["", "## Findings"])
        if report_json["findings"]:
            for item in report_json["findings"]:
                md_lines.extend(
                    [
                        f"### {item['title']} [{item['severity']}]",
                        f"- Status: {item['status']}",
                        f"- Confidence: {item['confidence']}",
                        f"- Summary: {item['summary'] or '(none)'}",
                        f"- Evidence: {item['evidence'] or '(none)'}",
                        f"- Reproduction: {item['reproduction'] or '(not provided)'}",
                        f"- Remediation: {item['remediation'] or '(not provided)'}",
                        "",
                    ]
                )
        else:
            md_lines.append("- No promoted findings were recorded for this run.")
        md_lines.extend(["", "## Evidence Model"])
        md_lines.append("### Observations")
        if observation_facts:
            for fact in observation_facts[:80]:
                md_lines.append(f"- [{fact.kind}] {fact.value} (source={fact.source}, confidence={fact.confidence:.2f})")
        else:
            md_lines.append("- No observation facts captured.")
        md_lines.append("")
        md_lines.append("### Hypotheses")
        if hypothesis_facts:
            for fact in hypothesis_facts[:80]:
                meta = dict(fact.metadata_json or {})
                title = str(meta.get("title") or fact.value or fact.kind)
                status = str(meta.get("status") or "candidate")
                evidence = str(meta.get("evidence") or "")
                md_lines.append(f"- {title} [{status}]")
                if evidence:
                    md_lines.append(f"  - Evidence: {evidence}")
        else:
            md_lines.append("- No hypothesis vectors/chains captured.")
        md_lines.append("")
        md_lines.append("### Validated Results")
        if validated_findings:
            for finding in validated_findings:
                md_lines.append(f"- {finding.title} [{finding.severity}] (confidence={finding.confidence:.2f})")
                if finding.evidence:
                    md_lines.append(f"  - Evidence: {finding.evidence}")
                if finding.reproduction:
                    md_lines.append(f"  - Reproduction: {finding.reproduction}")
        else:
            md_lines.append("- No validated findings were recorded in this run.")
        md_lines.extend(["", "## Proof Of Concept Notes"])
        for line in exec_evidence[:40]:
            md_lines.append(f"- {line}")
        md_lines.extend(["", "## Browser Assessment"])
        if browser_summary["enabled"]:
            md_lines.append(f"- Authenticated state: {browser_summary['authenticated']}")
            md_lines.append(f"- Pages visited: {browser_summary['pages_visited']}")
            md_lines.append(f"- Routes discovered: {browser_summary['routes_discovered']}")
            md_lines.append(f"- Forms discovered: {browser_summary['forms_discovered']}")
            md_lines.append(f"- Browser artifacts: {browser_summary['artifact_count']}")
            if browser_summary["auth_transitions"]:
                md_lines.append("- Auth/session transitions:")
                for item in browser_summary["auth_transitions"][:8]:
                    md_lines.append(
                        f"  - {item.get('stage', 'state')} status={item.get('status', 'observed')} url={item.get('url', '(none)')}"
                    )
            if browser_summary["dom_diffs"]:
                md_lines.append("- Browser state deltas:")
                for item in browser_summary["dom_diffs"][:8]:
                    md_lines.append(
                        f"  - {item.get('stage', 'navigation')}: forms={item.get('form_delta', 0)} links={item.get('link_delta', 0)} cookies={item.get('cookie_delta', 0)}"
                    )
            if browser_summary["route_hints"]:
                md_lines.append("- Hidden/privileged route hints:")
                for item in browser_summary["route_hints"][:10]:
                    md_lines.append(f"  - {item.get('hint', '(none)')} (page={item.get('url', '(unknown)')})")
            if browser_summary["js_signals"]:
                md_lines.append("- Client-side signals:")
                for item in browser_summary["js_signals"][:10]:
                    md_lines.append(
                        f"  - {item.get('kind', 'signal')}: {item.get('signal', '')} (page={item.get('url', '(unknown)')})"
                    )
            if browser_summary["blocked_actions"]:
                md_lines.append("- Policy-gated browser actions:")
                for item in browser_summary["blocked_actions"][:20]:
                    md_lines.append(f"  - {item}")
        else:
            md_lines.append("- Browser assessment was not executed for this run.")
        md_lines.extend(["", "## Artifacts With Provenance"])
        for art in report_json["artifacts"][:80]:
            md_lines.append(f"- {art['kind']}: {art['path']} (artifact_id={art['id']})")
        if report_json["negative_evidence"]:
            md_lines.extend(["", "## Negative Evidence"])
            for item in report_json["negative_evidence"][:40]:
                md_lines.append(f"- {item}")
        md_lines.extend(["", "## Approvals And Blocked Actions"])
        for event in report_json["events"]:
            if event["type"] in {"approval", "run_status"} or "blocked" in event["message"].lower():
                md_lines.append(f"- [{event['type']}] {event['message']}")
        md_lines.extend(
            [
                "",
                "## Remediation Roadmap",
                "- Prioritize findings marked high/critical and validate fixes with a focused re-test.",
                "- Reduce attack surface for externally exposed management and telemetry endpoints.",
                "- Preserve artifacts and timeline for customer handoff and audit retention.",
                "",
                "## Final Recommendation",
                "- Submit this report as the customer-facing baseline and append retest deltas after remediation.",
            ]
        )

        md_path = paths.artifacts / "run_report.md"
        json_path = paths.artifacts / "run_report.json"
        paths.write_text(Path(md_path), "\n".join(md_lines) + "\n")
        report_json["executive_summary"] = executive_summary
        paths.write_json(Path(json_path), report_json)
        comprehensive_payload = self._build_comprehensive_payload(
            run=run,
            facts=facts,
            findings=findings,
            events=events,
            artifacts=artifacts,
            executive_summary=executive_summary,
            port_values=port_values,
            service_values=service_values,
        )
        comprehensive_md = self._render_comprehensive_markdown(comprehensive_payload)
        comprehensive_md_path = paths.artifacts / "comprehensive_security_assessment_report.md"
        comprehensive_json_path = paths.artifacts / "comprehensive_security_assessment_report.json"
        artifact_index_json_path = paths.artifacts / "artifact_index.json"
        artifact_index_md_path = paths.artifacts / "artifact_index.md"
        timeline_csv_path = paths.artifacts / "timeline.csv"

        paths.write_text(comprehensive_md_path, comprehensive_md)
        paths.write_json(comprehensive_json_path, comprehensive_payload)
        artifact_index = self._build_artifact_index(run.id, artifacts)
        paths.write_json(artifact_index_json_path, artifact_index)
        paths.write_text(artifact_index_md_path, self._render_artifact_index_markdown(artifact_index))
        self._write_timeline_csv(timeline_csv_path, events)

        return {
            "markdown_path": str(md_path),
            "json_path": str(json_path),
            "summary": report_json,
            "comprehensive_markdown_path": str(comprehensive_md_path),
            "comprehensive_json_path": str(comprehensive_json_path),
            "artifact_index_path": str(artifact_index_json_path),
            "timeline_csv_path": str(timeline_csv_path),
        }

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
        if any(token in text for token in ["auth", "login", "jwt", "session", "password"]):
            return "authentication"
        if any(token in text for token in ["idor", "authorization", "access control", "privilege", "admin"]):
            return "authorization"
        if any(token in text for token in ["xss", "cross-site"]):
            return "xss"
        if any(token in text for token in ["sql", "injection", "command injection", "nosql", "xxe", "yaml"]):
            return "injection"
        if "ssrf" in text:
            return "ssrf"
        return "injection"

    def _extract_location(self, finding: Finding) -> str:
        text = " ".join([str(finding.evidence or ""), str(finding.summary or "")]).strip()
        if not text:
            return ""
        return text.splitlines()[0][:240]

    def _extract_prerequisites(self, finding: Finding) -> list[str]:
        base = []
        if finding.reproduction:
            if "token" in finding.reproduction.lower():
                base.append("Valid authentication token")
            if "admin" in finding.reproduction.lower():
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
        for key in ["authentication", "authorization", "xss", "injection", "ssrf"]:
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
