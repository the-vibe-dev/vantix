import os
import time
import tempfile
from pathlib import Path
from datetime import datetime

from fastapi.testclient import TestClient

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"
os.environ["SECOPS_RUNTIME_ROOT"] = str(Path(tempfile.gettempdir()) / f"secops_api_runtime_{os.getpid()}")

from secops.app import create_app
from secops.config import settings
from secops.db import Base, SessionLocal, engine
from secops.models import ApprovalRequest, Engagement, WorkerLease, WorkflowExecution, WorkflowPhaseRun, WorkspaceRun


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_modes_endpoint() -> None:
    reset_db()
    client = TestClient(create_app())
    response = client.get("/api/v1/modes")
    assert response.status_code == 200
    payload = response.json()
    assert any(item["id"] == "ctf" for item in payload)


def test_workflow_state_handles_naive_sqlite_datetimes() -> None:
    reset_db()
    client = TestClient(create_app())
    with SessionLocal() as db:
        engagement = Engagement(name="workflow-state", mode="pentest", target="10.10.10.10", tags=[])
        db.add(engagement)
        db.flush()
        run = WorkspaceRun(
            engagement_id=engagement.id,
            mode="pentest",
            workspace_id="ws-workflow-state",
            status="blocked",
            objective="test",
            target="10.10.10.10",
            config_json={},
        )
        db.add(run)
        db.flush()
        workflow = WorkflowExecution(run_id=run.id, status="running", current_phase="recon-sidecar")
        db.add(workflow)
        db.flush()
        # Explicitly write naive datetimes to mirror sqlite behavior and ensure
        # workflow-state calculations are timezone-safe.
        db.add(
            WorkflowPhaseRun(
                run_id=run.id,
                workflow_id=workflow.id,
                phase_name="recon-sidecar",
                attempt=1,
                status="blocked",
                worker_id="worker-local",
                started_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        )
        db.add(
            WorkerLease(
                run_id=run.id,
                workflow_id=workflow.id,
                phase_name="recon-sidecar",
                worker_id="worker-local",
                status="active",
                created_at=datetime.utcnow(),
                heartbeat_at=datetime.utcnow(),
                lease_expires_at=datetime.utcnow(),
            )
        )
        db.add(
            ApprovalRequest(
                run_id=run.id,
                title="Approval",
                detail="test",
                reason="recon_high_noise-policy",
                status="approved",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        )
        db.commit()
        run_id = run.id

    response = client.get(f"/api/v1/runs/{run_id}/workflow-state")
    assert response.status_code == 200
    payload = response.json()
    assert payload["metrics"]["current_claim_age_seconds"] >= 0.0
    assert payload["metrics"]["approval_latency_seconds_latest"] >= 0.0


def test_create_engagement_and_run() -> None:
    reset_db()
    client = TestClient(create_app())

    engagement = client.post(
        "/api/v1/engagements",
        json={
            "name": "Poster App",
            "mode": "ctf",
            "target": "10.10.10.10",
            "tags": ["ctf", "web"],
        },
    )
    assert engagement.status_code == 200
    engagement_id = engagement.json()["id"]

    run = client.post(
        "/api/v1/runs",
        json={
            "engagement_id": engagement_id,
            "objective": "Enumerate and validate the initial exploit path",
            "target": "10.10.10.10",
            "ports": ["80", "22"],
            "services": ["apache", "openssh"],
            "tags": ["web"],
        },
    )
    assert run.status_code == 200
    run_id = run.json()["id"]

    tasks = client.get(f"/api/v1/runs/{run_id}/tasks")
    assert tasks.status_code == 200
    assert len(tasks.json()) >= 3

    context = client.get(f"/api/v1/runs/{run_id}/context")
    assert context.status_code == 200
    assert "Learning Digest" in context.json()["assembled_prompt"] or "Learning Index" in context.json()["assembled_prompt"]


def test_start_run_creates_live_state_and_approval_when_codex_disabled() -> None:
    reset_db()
    old_codex = settings.enable_codex_execution
    old_script = settings.enable_script_execution
    object.__setattr__(settings, "enable_codex_execution", False)
    object.__setattr__(settings, "enable_script_execution", False)
    client = TestClient(create_app())

    try:
        engagement = client.post(
            "/api/v1/engagements",
            json={
                "name": "Live Run",
                "mode": "ctf",
                "target": "10.10.10.10",
                "tags": ["ctf"],
                "metadata": {"scope": {"allowed": ["10.10.10.10"], "allow_private": True}},
            },
        )
        engagement_id = engagement.json()["id"]
        run = client.post(
            "/api/v1/runs",
            json={"engagement_id": engagement_id, "objective": "Test live execution wiring", "target": "10.10.10.10"},
        )
        run_id = run.json()["id"]

        started = client.post(f"/api/v1/runs/{run_id}/start")
        assert started.status_code == 200

        terminal = {"content": ""}
        status = ""
        approvals = []
        for _ in range(50):
            time.sleep(0.2)
            graph = client.get(f"/api/v1/runs/{run_id}/graph")
            assert graph.status_code == 200
            graph_payload = graph.json()
            approvals = graph_payload["approvals"]
            status = graph_payload["status"]
            terminal = client.get(f"/api/v1/runs/{run_id}/terminal").json()
            if approvals and status in {"blocked", "cancelled", "completed", "failed"}:
                break

        assert approvals
        assert status == "blocked"
        assert (
            "disabled" in approvals[0]["reason"]
            or "codex" in approvals[0]["title"].lower()
            or "recon" in approvals[0]["reason"]
        )
        workflow_state = client.get(f"/api/v1/runs/{run_id}/workflow-state")
        assert workflow_state.status_code == 200
        workflow_payload = workflow_state.json()
        assert workflow_payload["run_id"] == run_id
        assert "metrics" in workflow_payload
        assert isinstance(workflow_payload["phases"], list)
        events = client.get(f"/api/v1/runs/{run_id}/events")
        assert events.status_code == 200
        assert any(event["event_type"] == "policy_decision" for event in events.json())
    finally:
        object.__setattr__(settings, "enable_codex_execution", old_codex)
        object.__setattr__(settings, "enable_script_execution", old_script)


def test_vantix_chat_creates_run_scheduler_state_and_vectors() -> None:
    reset_db()
    old_codex = settings.enable_codex_execution
    old_script = settings.enable_script_execution
    object.__setattr__(settings, "enable_codex_execution", False)
    object.__setattr__(settings, "enable_script_execution", False)
    client = TestClient(create_app())

    try:
        response = client.post("/api/v1/chat", json={"message": "Full test of 10.10.10.10", "mode": "pentest"})
        assert response.status_code == 200
        payload = response.json()
        run_id = payload["run"]["id"]
        assert payload["run"]["target"] == "10.10.10.10"
        assert payload["started"] is True

        messages = client.get(f"/api/v1/runs/{run_id}/messages")
        assert messages.status_code == 200
        assert [item["role"] for item in messages.json()] == ["user", "orchestrator"]

        graph = client.get(f"/api/v1/runs/{run_id}/graph")
        assert graph.status_code == 200
        graph_payload = graph.json()
        assert graph_payload["phase"]["current"] in {"knowledge-load", "research", "recon", "planning"}
        task_kinds = [task["kind"] for task in graph_payload["tasks"]]
        assert "vantix-recon" in task_kinds
        assert "flow-initialization" in task_kinds
        assert {agent["role"] for agent in graph_payload["agents"]} == {"orchestrator", "recon"}

        phase = client.get(f"/api/v1/runs/{run_id}/phase")
        assert phase.status_code == 200
        assert phase.json()["current"] in {"knowledge-load", "research", "recon", "planning"}

        vectors = client.get(f"/api/v1/runs/{run_id}/vectors")
        assert vectors.status_code == 200
        assert isinstance(vectors.json(), list)

        skills = client.get(f"/api/v1/runs/{run_id}/skills")
        assert skills.status_code == 200
        skill_payload = skills.json()
        assert skill_payload
        assert any(item["agent_role"] == "orchestrator" for item in skill_payload)
        assert any(skill["id"] == "scope_guard" for item in skill_payload for skill in item["skills"])
        assert any(Path(item["prompt_path"]).exists() for item in skill_payload)

        source_status = client.get(f"/api/v1/runs/{run_id}/source-status")
        assert source_status.status_code == 200
        assert source_status.json()["source_input"]["type"] == "none"

        handoff = client.get(f"/api/v1/runs/{run_id}/handoff")
        assert handoff.status_code == 200
        handoff_payload = handoff.json()
        assert handoff_payload["target"] == "10.10.10.10"
        assert handoff_payload["next_actions"]

        chain = client.post(
            f"/api/v1/runs/{run_id}/attack-chains",
            json={
                "name": "Recon to validated finding",
                "score": 72,
                "steps": [{"phase": "recon"}, {"phase": "validate"}],
                "mitre_ids": ["T1595"],
                "notes": "test chain",
            },
        )
        assert chain.status_code == 200
        assert chain.json()["score"] == 72
        chains = client.get(f"/api/v1/runs/{run_id}/attack-chains")
        assert chains.status_code == 200
        assert any(item["name"] == "Recon to validated finding" for item in chains.json())
        assert "provenance" in chains.json()[0]

        planning = client.get(f"/api/v1/runs/{run_id}/planning-bundle")
        assert planning.status_code == 200
        planning_payload = planning.json()
        assert planning_payload["run_id"] == run_id
        assert "best_vectors" in planning_payload
        assert "missing_evidence" in planning_payload

        created = client.post(
            f"/api/v1/runs/{run_id}/vectors",
            json={"title": "Manual validation path", "summary": "operator supplied", "confidence": 0.9},
        )
        assert created.status_code == 200
        selected = client.post(f"/api/v1/runs/{run_id}/vectors/{created.json()['id']}/select")
        assert selected.status_code == 200
        assert selected.json()["status"] == "planned"

        promoted = client.post(
            f"/api/v1/runs/{run_id}/findings/promote",
            json={"source_kind": "vector", "source_id": created.json()["id"], "title": "Manual vector finding"},
        )
        assert promoted.status_code == 200
        assert promoted.json()["title"] == "Manual vector finding"

        chain_promoted = client.post(
            f"/api/v1/runs/{run_id}/findings/promote",
            json={"source_kind": "attack_chain", "source_id": chain.json()["id"]},
        )
        assert chain_promoted.status_code == 200
        assert chain_promoted.json()["severity"] in {"medium", "high", "critical", "low"}

        findings = client.get(f"/api/v1/runs/{run_id}/findings")
        assert findings.status_code == 200
        assert len(findings.json()) >= 2

        results = client.get(f"/api/v1/runs/{run_id}/results")
        assert results.status_code == 200
        assert results.json()["run_id"] == run_id

        events = client.get(f"/api/v1/runs/{run_id}/events")
        assert events.status_code == 200
        event_types = {item["event_type"] for item in events.json()}
        assert "vector_generated" in event_types
        assert "attack_chain_generated" in event_types
        assert "finding_promoted" in event_types

        workflow_state = client.get(f"/api/v1/runs/{run_id}/workflow-state")
        assert workflow_state.status_code == 200
        metrics = workflow_state.json()["metrics"]
        assert "approval_pending_count" in metrics
        assert "phase_durations_seconds" in metrics
        assert "current_phase_duration_seconds" in metrics
    finally:
        object.__setattr__(settings, "enable_codex_execution", old_codex)
        object.__setattr__(settings, "enable_script_execution", old_script)


def test_vantix_quick_scan_starts_recon_only_and_approval_resumes() -> None:
    reset_db()
    old_codex = settings.enable_codex_execution
    old_script = settings.enable_script_execution
    object.__setattr__(settings, "enable_codex_execution", False)
    object.__setattr__(settings, "enable_script_execution", True)
    client = TestClient(create_app())

    try:
        response = client.post("/api/v1/chat", json={"message": "Run a quick scan on 10.10.10.10", "mode": "pentest"})
        assert response.status_code == 200
        payload = response.json()
        run_id = payload["run"]["id"]
        assert payload["run"]["config"]["scan_profile"] == "quick"
        messages = client.get(f"/api/v1/runs/{run_id}/messages")
        assert messages.status_code == 200
        assert "Recon-only quick scan" in messages.json()[-1]["content"]

        approvals = []
        for _ in range(80):
            time.sleep(0.2)
            graph = client.get(f"/api/v1/runs/{run_id}/graph")
            assert graph.status_code == 200
            gp = graph.json()
            approvals = gp["approvals"]
            if any(item["reason"] == "recon_high_noise-policy" and item["status"] == "pending" for item in approvals):
                break
        recon_gate = next(item for item in approvals if item["reason"] == "recon_high_noise-policy")
        approved = client.post(f"/api/v1/approvals/{recon_gate['id']}/approve", json={"note": "continue"})
        assert approved.status_code == 200

        quick_gate_id = ""
        for _ in range(120):
            time.sleep(0.2)
            graph = client.get(f"/api/v1/runs/{run_id}")
            assert graph.status_code == 200
            run_payload = graph.json()
            approvals = client.get(f"/api/v1/runs/{run_id}/approvals").json()
            recon_pending = [item for item in approvals if item["reason"] == "recon_high_noise-policy" and item["status"] == "pending"]
            if recon_pending:
                raise AssertionError("recon_high_noise-policy approval re-prompted after approval")
            quick_pending = [item for item in approvals if item["reason"] == "quick-scan-gate" and item["status"] == "pending"]
            if quick_pending:
                quick_gate_id = quick_pending[0]["id"]
                break
            if run_payload["status"] in {"blocked", "failed", "cancelled"}:
                # keep polling while workflow moves to quick scan gate
                pass
        assert quick_gate_id
        approved_quick = client.post(f"/api/v1/approvals/{quick_gate_id}/approve", json={"note": "continue to full flow"})
        assert approved_quick.status_code == 200

        for _ in range(80):
            time.sleep(0.2)
            run_payload = client.get(f"/api/v1/runs/{run_id}").json()
            if run_payload["config"].get("scan_profile") == "full":
                break
        graph_after_quick = client.get(f"/api/v1/runs/{run_id}/graph")
        assert graph_after_quick.status_code == 200
        roles = {agent["role"] for agent in graph_after_quick.json()["agents"]}
        assert roles == {"orchestrator", "recon"}

        skills = client.get(f"/api/v1/runs/{run_id}/skills")
        assert skills.status_code == 200
        payload = skills.json()
        skills_by_role = {item["agent_role"]: item["skills"] for item in payload}
        assert len(skills_by_role.get("orchestrator", [])) > 0
        assert "knowledge_base" not in skills_by_role
        assert "researcher" not in skills_by_role

        terminal = client.get(f"/api/v1/runs/{run_id}/terminal")
        assert terminal.status_code == 200
        content = terminal.json()["content"]
        assert "[recon] starting:" in content
        assert "[recon] blocked by policy:" in content

        events = client.get(f"/api/v1/runs/{run_id}/events")
        assert events.status_code == 200
        event_types = {item["event_type"] for item in events.json()}
        assert "approval_requested" in event_types
        assert "approval_resolved" in event_types
    finally:
        object.__setattr__(settings, "enable_codex_execution", old_codex)
        object.__setattr__(settings, "enable_script_execution", old_script)


def test_vantix_chat_requires_target_for_new_run_and_appends_existing_run() -> None:
    reset_db()
    old_codex = settings.enable_codex_execution
    object.__setattr__(settings, "enable_codex_execution", False)
    client = TestClient(create_app())

    try:
        rejected = client.post("/api/v1/chat", json={"message": "start a full test"})
        assert rejected.status_code == 400

        first = client.post("/api/v1/chat", json={"message": "Full test of https://example.test", "mode": "bugbounty"})
        assert first.status_code == 200
        run_id = first.json()["run"]["id"]
        follow_up = client.post("/api/v1/chat", json={"run_id": run_id, "message": "Prioritize web evidence and keep scans low noise."})
        assert follow_up.status_code == 200
        assert follow_up.json()["started"] is False

        messages = client.get(f"/api/v1/runs/{run_id}/messages").json()
        assert [item["role"] for item in messages].count("user") == 2
        notes = client.get(f"/api/v1/runs/{run_id}/notes")
        assert notes.status_code == 200
        assert any("Prioritize web evidence" in item["content"] for item in notes.json())
    finally:
        object.__setattr__(settings, "enable_codex_execution", old_codex)


def test_vantix_chat_with_run_id_can_start_new_engagement_when_requested() -> None:
    reset_db()
    old_codex = settings.enable_codex_execution
    object.__setattr__(settings, "enable_codex_execution", False)
    client = TestClient(create_app())

    try:
        first = client.post("/api/v1/chat", json={"message": "Run a quick scan on 192.168.1.95", "mode": "pentest"})
        assert first.status_code == 200
        old_run_id = first.json()["run"]["id"]

        cancel = client.post(f"/api/v1/runs/{old_run_id}/cancel")
        assert cancel.status_code == 200

        new_req = client.post(
            "/api/v1/chat",
            json={
                "run_id": old_run_id,
                "message": "Start a new engagement on 192.168.1.99 go through all phases",
            },
        )
        assert new_req.status_code == 200
        payload = new_req.json()
        assert payload["started"] is True
        assert payload["run"]["id"] != old_run_id
        assert payload["run"]["target"] == "192.168.1.99"

        old_run = client.get(f"/api/v1/runs/{old_run_id}")
        assert old_run.status_code == 200
        assert old_run.json()["target"] == "192.168.1.95"
    finally:
        object.__setattr__(settings, "enable_codex_execution", old_codex)


def test_vantix_chat_with_terminal_run_and_new_target_starts_new_without_strict_phrase() -> None:
    reset_db()
    old_codex = settings.enable_codex_execution
    object.__setattr__(settings, "enable_codex_execution", False)
    client = TestClient(create_app())

    try:
        first = client.post("/api/v1/chat", json={"message": "Run recon on 192.168.1.95", "mode": "pentest"})
        assert first.status_code == 200
        old_run_id = first.json()["run"]["id"]
        assert client.post(f"/api/v1/runs/{old_run_id}/cancel").status_code == 200

        follow = client.post(
            "/api/v1/chat",
            json={"run_id": old_run_id, "message": "scan 192.168.1.99 and continue through phases"},
        )
        assert follow.status_code == 200
        payload = follow.json()
        assert payload["started"] is True
        assert payload["run"]["id"] != old_run_id
        assert payload["run"]["target"] == "192.168.1.99"
    finally:
        object.__setattr__(settings, "enable_codex_execution", old_codex)


def test_vantix_system_status_and_provider_secret_handling() -> None:
    reset_db()
    old_secret = settings.secret_key
    client = TestClient(create_app())

    try:
        status = client.get("/api/v1/system/status")
        assert status.status_code == 200
        status_payload = status.json()
        assert status_payload["product"] == "Vantix"
        assert "api_token" not in str(status_payload).lower()

        plain = client.post("/api/v1/providers", json={"name": "Local Ollama", "provider_type": "ollama", "base_url": "http://127.0.0.1:11434"})
        assert plain.status_code == 200
        assert plain.json()["has_key"] is False
        assert "secret" not in plain.json()

        object.__setattr__(settings, "secret_key", "")
        rejected = client.post("/api/v1/providers", json={"name": "OpenAI", "provider_type": "openai", "secret": "sk-test"})
        assert rejected.status_code == 400

        object.__setattr__(settings, "secret_key", "unit-test-key")
        stored = client.post("/api/v1/providers", json={"name": "OpenAI", "provider_type": "openai", "secret": "sk-test"})
        assert stored.status_code == 200
        stored_payload = stored.json()
        assert stored_payload["has_key"] is True
        assert "sk-test" not in str(stored_payload)

        engagement = client.post("/api/v1/engagements", json={"name": "Route Test", "mode": "pentest", "target": "10.10.10.10"}).json()
        run = client.post("/api/v1/runs", json={"engagement_id": engagement["id"], "objective": "Route provider", "target": "10.10.10.10"}).json()
        routed = client.post(f"/api/v1/runs/{run['id']}/provider-route", json={"provider_id": stored_payload["id"]})
        assert routed.status_code == 200
        assert routed.json()["config"]["provider_id"] == stored_payload["id"]

        reset_route = client.post(f"/api/v1/runs/{run['id']}/provider-route", json={"provider_id": ""})
        assert reset_route.status_code == 200
        assert reset_route.json()["config"]["runtime_route"]["runtime"] == "codex"
    finally:
        object.__setattr__(settings, "secret_key", old_secret)


def test_skill_pack_crud_and_reload() -> None:
    reset_db()
    client = TestClient(create_app())

    created = client.post(
        "/api/v1/skills",
        json={
            "id": "local_test_pack",
            "name": "Local Test Pack",
            "summary": "operator managed",
            "roles": ["orchestrator"],
            "modes": ["pentest"],
            "tags": ["local"],
            "body": "# Local Test Pack\n\nUse local extension.",
        },
    )
    assert created.status_code == 200
    assert created.json()["editable"] is True

    updated = client.put(
        "/api/v1/skills/local_test_pack",
        json={"summary": "updated summary", "body": "# Local Test Pack\n\nUpdated body."},
    )
    assert updated.status_code == 200
    assert updated.json()["summary"] == "updated summary"
    assert updated.json()["version"] >= 2

    listing = client.get("/api/v1/skills")
    assert listing.status_code == 200
    assert any(item["id"] == "local_test_pack" and item["editable"] for item in listing.json())

    reloaded = client.post("/api/v1/skills/reload")
    assert reloaded.status_code == 200
    assert reloaded.json()["count"] >= 1
    assert any(item["id"] == "local_test_pack" for item in reloaded.json()["skills"])

    deleted = client.delete("/api/v1/skills/local_test_pack")
    assert deleted.status_code == 204
