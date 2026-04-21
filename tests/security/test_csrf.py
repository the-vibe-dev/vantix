"""PRA-014: CSRF double-submit on mutating routes."""
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
    set_setting("enable_background_worker", False)
    with TestClient(create_app()) as client:
        yield client


def test_mutating_post_without_csrf_header_rejected(client: TestClient) -> None:
    as_user(client, "operator")
    resp = client.post("/api/v1/chat", json={"message": "hi", "mode": "pentest"})
    assert resp.status_code == 403
    assert "CSRF" in resp.json()["detail"].upper()


def test_mutating_post_with_matching_csrf_accepted(client: TestClient) -> None:
    csrf = as_user(client, "admin")
    # Logout is a safe mutating endpoint to assert CSRF acceptance shape.
    resp = client.post("/api/v1/auth/logout", headers={"x-csrf-token": csrf})
    assert resp.status_code == 200


def test_mismatched_csrf_rejected(client: TestClient) -> None:
    as_user(client, "operator")
    resp = client.post(
        "/api/v1/chat",
        json={"message": "hi", "mode": "pentest"},
        headers={"x-csrf-token": "not-the-real-token"},
    )
    assert resp.status_code == 403


def test_get_does_not_require_csrf(client: TestClient) -> None:
    as_user(client, "viewer")
    assert client.get("/api/v1/modes").status_code == 200
