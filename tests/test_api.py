import os
import time
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

from secops.app import create_app
from secops.config import settings
from secops.db import Base, engine


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
            json={"name": "Live Run", "mode": "ctf", "target": "10.10.10.10", "tags": ["ctf"]},
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
        assert "disabled" in approvals[0]["reason"] or "Codex" in approvals[0]["title"]
        assert "disabled" in terminal["content"].lower()
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
        task_kinds = [task["kind"] for task in graph_payload["tasks"]]
        assert "vantix-recon" in task_kinds
        assert "vector-store" in task_kinds
        assert {agent["role"] for agent in graph_payload["agents"]} >= {"orchestrator", "recon", "researcher", "executor"}

        vectors = client.get(f"/api/v1/runs/{run_id}/vectors")
        assert vectors.status_code == 200
        assert vectors.json()[0]["source"] == "scheduler"

        skills = client.get(f"/api/v1/runs/{run_id}/skills")
        assert skills.status_code == 200
        skill_payload = skills.json()
        assert skill_payload
        assert any(item["agent_role"] == "orchestrator" for item in skill_payload)
        assert any(skill["id"] == "scope_guard" for item in skill_payload for skill in item["skills"])
        assert any(Path(item["prompt_path"]).exists() for item in skill_payload)

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

        created = client.post(
            f"/api/v1/runs/{run_id}/vectors",
            json={"title": "Manual validation path", "summary": "operator supplied", "confidence": 0.9},
        )
        assert created.status_code == 200
        selected = client.post(f"/api/v1/runs/{run_id}/vectors/{created.json()['id']}/select")
        assert selected.status_code == 200
        assert selected.json()["status"] == "planned"

        results = client.get(f"/api/v1/runs/{run_id}/results")
        assert results.status_code == 200
        assert results.json()["run_id"] == run_id
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
    finally:
        object.__setattr__(settings, "secret_key", old_secret)
