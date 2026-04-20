from __future__ import annotations

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
            f"Validated findings: {len(high_conf_findings)}. CVE references: {len(cve_values)}."
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
        return {"markdown_path": str(md_path), "json_path": str(json_path), "summary": report_json}
