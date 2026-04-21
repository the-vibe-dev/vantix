import os

from fastapi.testclient import TestClient

os.environ["SECOPS_ENABLE_BACKGROUND_WORKER"] = "0"

from secops.app import create_app
from secops.services.skills import SkillRegistry


def test_skill_registry_loads_restricted_packs() -> None:
    registry = SkillRegistry()
    packs = {pack.id: pack for pack in registry.all()}

    assert {"scope_guard", "swarm_orchestrator", "web_hunter", "api_security", "report_generator"} <= set(packs)
    assert packs["social_engineer"].execution_level == "advisory"
    assert packs["malware_analyst"].execution_level == "advisory"
    assert packs["credential_tester"].execution_level == "gated"
    assert "credential_theft" in packs["credential_tester"].forbidden
    assert "PentAGI" not in "\n".join(pack.body for pack in packs.values())


def test_skill_catalog_endpoint() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/skills")
        assert response.status_code == 200
        payload = response.json()
        assert any(item["id"] == "scope_guard" for item in payload)
