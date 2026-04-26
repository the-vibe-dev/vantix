from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from secops.models import Artifact, Fact, WorkspaceRun
from secops.services.storage import StorageLayout

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from secops.services.scope import ScopeVerdict


class ScopeMixin:
    """Target normalization and engagement-scope enforcement.

    Extracted from ExecutionManager. Methods retain ``self`` access
    so cross-mixin callers (``self._run_command``, ``self.events``)
    continue to resolve through MRO without changes.
    """

    def _recon_target(self, target: str) -> str:
        if not target:
            return ""
        parsed = urlparse(target)
        if parsed.scheme and parsed.hostname:
            return parsed.hostname
        return target

    def _enforce_scope(self, db: "Session", run: "WorkspaceRun", target: str) -> "ScopeVerdict":
        """Resolve engagement scope metadata and validate target.

        Returns a ScopeVerdict; callers must block when not allowed.
        A granted ``scope-policy`` approval is consumed as a one-time override.
        """
        from secops.models import Engagement
        from secops.services.scope import ScopeVerdict, is_scope_allowed

        engagement = db.get(Engagement, run.engagement_id) if run.engagement_id else None
        scope = {}
        if engagement is not None and isinstance(engagement.metadata_json, dict):
            raw = engagement.metadata_json.get("scope")
            if isinstance(raw, dict):
                scope = raw
        allowed = scope.get("allowed") or []
        excludes = scope.get("excludes") or []
        allow_private = bool(scope.get("allow_private", False))
        config = dict(run.config_json or {})
        scope_overrides = dict(config.get("scope_overrides") or {})
        if bool(scope_overrides.get(target)):
            allow_private = True
        grants_raw = config.get("approval_grants")
        grants = dict(grants_raw) if isinstance(grants_raw, dict) else {}
        scope_grants = int(grants.get("scope", 0) or 0)
        if scope_grants > 0:
            grants["scope"] = scope_grants - 1
            config["approval_grants"] = grants
            run.config_json = config
            allow_private = True
        if engagement and engagement.target and engagement.target not in allowed:
            allowed = list(allowed) + [engagement.target]
        return is_scope_allowed(target, allowed=allowed, excludes=excludes, allow_private=allow_private)

    def _should_escalate_recon(self, run: WorkspaceRun, discovered: dict[str, list[str]]) -> bool:
        cfg = dict(run.config_json or {})
        if str(cfg.get("scan_profile", "full")).lower() == "quick":
            return False
        if bool(cfg.get("recon_escalated")):
            return False
        if cfg.get("ports"):
            return False
        ports = [int(port) for port in discovered.get("ports", []) if str(port).isdigit()]
        if not ports:
            return True
        high_port_present = any(port >= 10000 for port in ports)
        if len(ports) < 8:
            return True
        return not high_port_present

    def _web_followup_checks(
        self,
        *,
        db,
        run: WorkspaceRun,
        recon_target: str,
        discovered: dict[str, list[str]],
        session_id: str,
        paths: StorageLayout,
    ) -> dict:
        if not recon_target:
            return {"checked_ports": 0, "hits": 0, "checks": 0}
        cfg = dict(run.config_json or {})
        if str(cfg.get("scan_profile", "full")).lower() == "quick":
            return {"checked_ports": 0, "hits": 0, "checks": 0, "skipped": "quick-scan-profile"}
        if bool(cfg.get("web_followup_done")):
            return {"checked_ports": 0, "hits": 0, "checks": 0, "skipped": "already-done"}
        ports = [port for port in discovered.get("ports", []) if str(port).isdigit()]
        if not ports:
            return {"checked_ports": 0, "hits": 0, "checks": 0}

        candidate_ports = []
        for port in ports:
            p = int(port)
            if p in {80, 443, 3000, 5000, 8000, 8080, 8443} or p >= 1024:
                candidate_ports.append(str(p))
        candidate_ports = sorted(set(candidate_ports), key=lambda value: int(value))
        if not candidate_ports:
            return {"checked_ports": 0, "hits": 0, "checks": 0}

        source_paths = ["/server.py", "/app.py", "/main.py", "/.env", "/.git/config"]
        traversal_paths = ["/../../etc/passwd", "/..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd"]
        issues: list[dict[str, str]] = []
        checks = 0
        sample_lines: list[str] = []
        for port in candidate_ports[:10]:
            base_url = f"http://{recon_target}:{port}"
            probe = self._run_command(["curl", "-sS", "-L", "--max-time", "4", base_url + "/"], str(paths.logs / "recon.log"), run_id=run.id)
            checks += 1
            if "HTTP/" not in probe and "<html" not in probe.lower() and "command failed" in probe.lower():
                continue
            for path in source_paths:
                resp = self._run_command(["curl", "-sS", "-L", "--max-time", "4", base_url + path], str(paths.logs / "recon.log"), run_id=run.id)
                checks += 1
                body = resp.lower()
                if "import " in body or "def " in body or "flask" in body or "django" in body:
                    issues.append({"port": port, "kind": "source-disclosure", "path": path, "evidence": f"{base_url}{path}"})
                    sample_lines.append(f"[web] potential source disclosure: {base_url}{path}")
                    break
            for path in traversal_paths:
                resp = self._run_command(
                    ["curl", "-sS", "-L", "--path-as-is", "--max-time", "4", base_url + path],
                    str(paths.logs / "recon.log"),
                    run_id=run.id,
                )
                checks += 1
                text = resp.lower()
                if "root:x:" in text or "/bin/bash" in text:
                    issues.append({"port": port, "kind": "path-traversal-read", "path": path, "evidence": f"{base_url}{path}"})
                    sample_lines.append(f"[web] potential traversal file-read: {base_url}{path}")
                    break

        for issue in issues:
            db.add(
                Fact(
                    run_id=run.id,
                    source="recon-web",
                    kind="vector",
                    value=f"{issue['kind']} on {issue['port']}",
                    confidence=0.85,
                    tags=["web", "candidate"],
                    metadata_json={
                        "title": issue["kind"],
                        "summary": f"Potential {issue['kind']} identified during automated web validation.",
                        "status": "candidate",
                        "severity": "high",
                        "evidence": issue["evidence"],
                        "next_action": "validate safely and capture proof",
                        "port": issue["port"],
                        "path": issue["path"],
                        "source": "recon-web",
                    },
                )
            )
        for line in sample_lines[:20]:
            self.events.emit(
                db,
                run.id,
                "terminal",
                line,
                payload={"agent": "recon", "stage": "web-followup"},
                agent_session_id=session_id,
            )
        cfg["web_followup_done"] = True
        run.config_json = cfg
        if issues:
            report_path = paths.logs / "web-followup.json"
            paths.write_json(report_path, {"target": recon_target, "issues": issues, "checks": checks})
            db.add(Artifact(run_id=run.id, kind="web-followup", path=str(report_path), metadata_json={"hits": len(issues), "checks": checks}))
        return {"checked_ports": len(candidate_ports[:10]), "hits": len(issues), "checks": checks}
