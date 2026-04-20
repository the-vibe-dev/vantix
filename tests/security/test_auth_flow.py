"""PRA-014: cookie-auth login/logout/me happy and failure paths."""
from __future__ import annotations

from tests.security._helpers import isolated_db_env

isolated_db_env()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from secops.app import create_app  # noqa: E402
from tests.security._helpers import (  # noqa: E402
    as_user,
    create_user,
    login_as,
    reset_db,
    set_setting,
)


@pytest.fixture
def client() -> TestClient:
    reset_db()
    set_setting("dev_mode", False)
    set_setting("service_token_enabled", False)
    return TestClient(create_app())


def test_login_happy_path_sets_cookies(client: TestClient) -> None:
    create_user("op1", "pw-one-two-three", "operator")
    resp = client.post("/api/v1/auth/login", json={"username": "op1", "password": "pw-one-two-three"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"] == {"username": "op1", "role": "operator"}
    assert data["csrf"]
    assert "vantix_session" in client.cookies
    assert "vantix_csrf" in client.cookies


def test_login_wrong_password_rejected(client: TestClient) -> None:
    create_user("op1", "real-password", "operator")
    resp = client.post("/api/v1/auth/login", json={"username": "op1", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user_rejected(client: TestClient) -> None:
    resp = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "x"})
    assert resp.status_code == 401


def test_me_requires_session(client: TestClient) -> None:
    assert client.get("/api/v1/auth/me").status_code == 401
    as_user(client, "viewer")
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json() == {"username": "viewer_user", "role": "viewer"}


def test_logout_revokes_session(client: TestClient) -> None:
    as_user(client, "operator")
    assert client.get("/api/v1/auth/me").status_code == 200
    # logout is a mutating POST → requires CSRF header
    csrf = client.cookies.get("vantix_csrf")
    resp = client.post("/api/v1/auth/logout", headers={"x-csrf-token": csrf})
    assert resp.status_code == 200
    # Cookie is cleared client-side. Even if an attacker replays the old cookie,
    # the server-side session is revoked.
    client.cookies.set("vantix_session", client.cookies.get("vantix_session") or "stale")
    assert client.get("/api/v1/auth/me").status_code == 401


def test_disabled_user_cannot_login(client: TestClient) -> None:
    create_user("op1", "pw", "operator")
    from secops.db import SessionLocal
    from secops.models import User

    with SessionLocal() as db:
        u = db.query(User).filter(User.username == "op1").first()
        u.disabled = True
        db.commit()
    resp = client.post("/api/v1/auth/login", json={"username": "op1", "password": "pw"})
    assert resp.status_code == 401


def test_login_rate_limited(client: TestClient) -> None:
    create_user("op1", "real-pw", "operator")
    # 5 allowed, 6th should 429
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"username": "op1", "password": "bad"})
    final = client.post("/api/v1/auth/login", json={"username": "op1", "password": "bad"})
    assert final.status_code == 429


def test_session_ttl_expiry_rejected(client: TestClient) -> None:
    create_user("op1", "pw", "operator")
    login_as(client, "op1", "pw")
    # Force-expire the server-side session
    from datetime import timedelta

    from secops.db import SessionLocal
    from secops.models import UserSession
    from secops.services.auth_service import utcnow

    with SessionLocal() as db:
        for row in db.query(UserSession).all():
            row.expires_at = utcnow() - timedelta(hours=1)
        db.commit()

    assert client.get("/api/v1/auth/me").status_code == 401
