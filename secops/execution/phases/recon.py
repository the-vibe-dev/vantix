from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secops.db import SessionLocal
from secops.models import Artifact, Fact, RunMessage, WorkspaceRun


class ReconPhaseMixin:
    """Recon-sidecar phase: nmap discovery, scope enforcement, web follow-ups.

    Extracted from ExecutionManager. Relies on ``self.nas``, ``self.events``,
    ``self.policies`` and helpers (``_task_by_kind``, ``_create_agent_session``,
    ``_set_role_status``, ``_recon_target``, ``_enforce_scope``,
    ``_emit_policy_decision``, ``_create_approval``, ``_run_command``,
    ``_emit_terminal_excerpt``, ``_parse_nmap``, ``_should_escalate_recon``,
    ``_web_followup_checks``, ``_set_vantix_task_status``, ``_write_memory``)
    from peer mixins.
    """

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
            facts = [["port", port] for port in discovered["ports"]] + [["service", service] for service in discovered["services"]]
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
