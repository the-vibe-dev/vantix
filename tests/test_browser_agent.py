from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_browser_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"
os.environ["SECOPS_RUNTIME_ROOT"] = str(Path(tempfile.gettempdir()) / f"secops_browser_runtime_{os.getpid()}")

from secops.db import Base, SessionLocal, engine
from secops.models import ApprovalRequest, Artifact, Engagement, Fact, Task, WorkspaceRun
from secops.routers.runs import get_browser_state
from secops.services.browser_runtime import BrowserAssessmentResult, BrowserObservation, BrowserRuntimeService, _sanitize_headers
from secops.services.execution import ExecutionManager


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed_run() -> str:
    with SessionLocal() as db:
        engagement = Engagement(name="Browser Test", mode="pentest", target="http://127.0.0.1:8080", tags=["pentest"])
        db.add(engagement)
        db.flush()
        run = WorkspaceRun(
            engagement_id=engagement.id,
            mode="pentest",
            workspace_id="pentest-browser-test",
            status="queued",
            objective="browser test",
            target="http://127.0.0.1:8080",
            config_json={"browser": {"entry_url": "http://127.0.0.1:8080", "enabled": True}, "tags": ["pentest", "vantix"]},
        )
        db.add(run)
        db.flush()
        for idx, kind in enumerate(["browser-assessment"], start=1):
            db.add(Task(run_id=run.id, name=kind, description=kind, kind=kind, status="pending", sequence=idx))
        db.commit()
        return run.id


def test_browser_runtime_parsers_and_safety_helpers() -> None:
    runtime = BrowserRuntimeService()
    forms = runtime._extract_forms(
        '<form method="post" action="/login"><input name="username"><input type="password" name="password"></form>'
    )
    assert forms
    assert forms[0]["auth_like"] is True
    links = runtime._extract_links('<a href="/admin">admin</a><a href="http://127.0.0.1:8080/x">x</a>', "http://127.0.0.1:8080")
    assert any(item.endswith("/admin") for item in links)
    cleaned = _sanitize_headers({"Authorization": "Bearer secret", "x-test": "ok"})
    assert cleaned["Authorization"] == "[REDACTED]"
    assert cleaned["x-test"] == "ok"
    assert runtime._is_sensitive_route("http://127.0.0.1:8080/admin")


def test_browser_phase_generates_facts_vectors_and_artifacts() -> None:
    reset_db()
    run_id = _seed_run()
    manager = ExecutionManager()

    def _fake_assess(**_: object) -> BrowserAssessmentResult:
        tmp_root = Path(tempfile.gettempdir()) / "vantix-browser-test-artifacts"
        tmp_root.mkdir(parents=True, exist_ok=True)
        route_path = tmp_root / "route-discovery.json"
        form_path = tmp_root / "form-map.json"
        net_path = tmp_root / "network-summary.json"
        sess_path = tmp_root / "browser-session-summary.json"
        dom_path = tmp_root / "dom-1.json"
        png_path = tmp_root / "shot-1.png"
        route_path.write_text(json.dumps({"edges": [{"from": "http://127.0.0.1:8080", "to": "http://127.0.0.1:8080/admin"}]}), encoding="utf-8")
        form_path.write_text(json.dumps({"forms": [{"url": "http://127.0.0.1:8080/login", "forms": [{"auth_like": True}]}]}), encoding="utf-8")
        net_path.write_text(json.dumps({"endpoints": [{"endpoint": "GET /api/users", "count": 3}], "total_requests": 12}), encoding="utf-8")
        sess_path.write_text(
            json.dumps(
                {
                    "entry_url": "http://127.0.0.1:8080",
                    "current_url": "http://127.0.0.1:8080/dashboard",
                    "authenticated": "partial",
                    "pages_visited": 2,
                    "blocked_actions": ["blocked-sensitive-route:http://127.0.0.1:8080/admin"],
                }
            ),
            encoding="utf-8",
        )
        dom_path.write_text("{}", encoding="utf-8")
        png_path.write_bytes(b"\x89PNG\r\n\x1a\n")
        return BrowserAssessmentResult(
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:10Z",
            entry_url="http://127.0.0.1:8080",
            current_url="http://127.0.0.1:8080/dashboard",
            authenticated="partial",
            observations=[
                BrowserObservation(
                    url="http://127.0.0.1:8080/login",
                    title="Login",
                    depth=1,
                    links=["http://127.0.0.1:8080/admin"],
                    forms=[{"id": "f1", "auth_like": True, "fields": [{"name": "password", "type": "password"}]}],
                    storage_summary={"cookie_count": 1},
                    scripts=["/assets/app.js"],
                )
            ],
            network_summary={"total_requests": 12, "endpoints": [{"endpoint": "GET /api/users", "count": 3}]},
            route_graph=[{"from": "http://127.0.0.1:8080", "to": "http://127.0.0.1:8080/admin"}],
            blocked_actions=["blocked-sensitive-route:http://127.0.0.1:8080/admin"],
            artifacts=[
                {"kind": "route-discovery", "path": str(route_path)},
                {"kind": "form-map", "path": str(form_path)},
                {"kind": "network-summary", "path": str(net_path)},
                {"kind": "browser-session-summary", "path": str(sess_path)},
                {"kind": "dom-snapshot", "path": str(dom_path)},
                {"kind": "screenshot", "path": str(png_path)},
            ],
        )

    manager.browser.assess = _fake_assess  # type: ignore[method-assign]
    manager._phase_browser(run_id)

    with SessionLocal() as db:
        run = db.get(WorkspaceRun, run_id)
        assert run is not None
        assert run.status in {"queued", "running"}
        artifacts = db.query(Artifact).filter(Artifact.run_id == run_id).all()
        kinds = {item.kind for item in artifacts}
        assert "browser-session-summary" in kinds
        assert "route-discovery" in kinds
        facts = db.query(Fact).filter(Fact.run_id == run_id).all()
        fact_kinds = {row.kind for row in facts}
        assert "route" in fact_kinds
        assert "form" in fact_kinds
        assert "api-endpoint" in fact_kinds
        assert "vector" in fact_kinds
        assert "attack_chain" in fact_kinds


def test_browser_state_endpoint_payload_shape() -> None:
    reset_db()
    run_id = _seed_run()
    with SessionLocal() as db:
        session_path = Path(tempfile.gettempdir()) / "vantix-browser-state-session.json"
        session_path.write_text(
            json.dumps(
                {
                    "entry_url": "http://127.0.0.1:8080",
                    "current_url": "http://127.0.0.1:8080/home",
                    "authenticated": "success",
                    "pages_visited": 4,
                    "blocked_actions": [],
                }
            ),
            encoding="utf-8",
        )
        route_path = Path(tempfile.gettempdir()) / "vantix-browser-state-route.json"
        route_path.write_text(
            json.dumps({"edges": [{"from": "http://127.0.0.1:8080", "to": "http://127.0.0.1:8080/admin"}]}),
            encoding="utf-8",
        )
        db.add(Artifact(run_id=run_id, kind="browser-session-summary", path=str(session_path), metadata_json={}))
        db.add(Artifact(run_id=run_id, kind="route-discovery", path=str(route_path), metadata_json={}))
        db.commit()

    with SessionLocal() as db:
        payload = get_browser_state(run_id, db)
    assert payload["run_id"] == run_id
    assert payload["authenticated"] == "success"
    assert payload["routes_discovered"] >= 1
    assert "artifacts" in payload


def test_browser_auth_flow_can_be_policy_blocked_with_approval() -> None:
    reset_db()
    run_id = _seed_run()
    with SessionLocal() as db:
        run = db.get(WorkspaceRun, run_id)
        assert run is not None
        run.config_json = {
            **(run.config_json or {}),
            "browser": {"entry_url": "http://127.0.0.1:8080", "enabled": True, "allow_auth": True},
            "browser_auth": {"login_url": "http://127.0.0.1:8080/login", "username": "operator", "password": "secret"},
        }
        db.commit()
    manager = ExecutionManager()
    manager._phase_browser(run_id)
    with SessionLocal() as db:
        run = db.get(WorkspaceRun, run_id)
        assert run is not None
        assert run.status == "blocked"
        approvals = db.query(ApprovalRequest).filter(ApprovalRequest.run_id == run_id).all()
        assert any("browser_auth-policy" in row.reason for row in approvals)
