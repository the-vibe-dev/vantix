"""PRA-014/029/044: role-based access regression tests."""
from __future__ import annotations

from tests.security._helpers import isolated_db_env

isolated_db_env()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from secops.app import create_app  # noqa: E402
from tests.security._helpers import as_user, reset_db, set_setting  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    reset_db()
    set_setting("dev_mode", False)
    set_setting("service_token_enabled", False)
    return TestClient(create_app())


def test_unauthenticated_rejected_on_viewer_route(client: TestClient) -> None:
    assert client.get("/api/v1/modes").status_code == 401


def test_viewer_can_read_viewer_routes(client: TestClient) -> None:
    as_user(client, "viewer")
    assert client.get("/api/v1/modes").status_code == 200
    assert client.get("/api/v1/tools").status_code == 200
    assert client.get("/api/v1/skills").status_code == 200


def test_viewer_cannot_hit_operator_routes(client: TestClient) -> None:
    as_user(client, "viewer")
    assert client.get("/api/v1/runs").status_code == 403


def test_viewer_cannot_hit_admin_routes(client: TestClient) -> None:
    as_user(client, "viewer")
    assert client.get("/api/v1/providers").status_code == 403


def test_operator_can_read_runs(client: TestClient) -> None:
    as_user(client, "operator")
    assert client.get("/api/v1/runs").status_code == 200


def test_operator_cannot_hit_admin_routes(client: TestClient) -> None:
    as_user(client, "operator")
    assert client.get("/api/v1/providers").status_code == 403
    assert client.get("/api/v1/system/health").status_code in (403, 404)


def test_admin_has_full_access(client: TestClient) -> None:
    as_user(client, "admin")
    assert client.get("/api/v1/runs").status_code == 200
    assert client.get("/api/v1/providers").status_code == 200
    assert client.get("/api/v1/modes").status_code == 200


def test_terminal_requires_operator_pra029(client: TestClient) -> None:
    """PRA-029 regression: run terminal output is operator-gated."""
    as_user(client, "viewer")
    # Any run ID works — viewer should 403 before the handler runs.
    resp = client.get("/api/v1/runs/some-run-id/terminal")
    assert resp.status_code == 403
