"""Shared helpers for auth/RBAC tests."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


def isolated_db_env() -> None:
    """Point SECOPS_DATABASE_URL at a fresh per-process sqlite file."""
    path = Path(tempfile.gettempdir()) / f"secops_auth_test_{os.getpid()}.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{path}"
    os.environ["SECOPS_DEV_MODE"] = "0"
    os.environ["SECOPS_ENABLE_BACKGROUND_WORKER"] = "0"


def reset_db() -> None:
    from secops.db import Base, engine

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def set_setting(field: str, value) -> None:
    from secops.config import settings

    object.__setattr__(settings, field, value)


def create_user(username: str, password: str, role: str) -> None:
    from secops.db import SessionLocal
    from secops.models import User
    from secops.services import auth_service

    with SessionLocal() as db:
        existing = db.query(User).filter(User.username == username).first()
        if existing is not None:
            existing.password_hash = auth_service.hash_password(password)
            existing.role = role
            existing.disabled = False
        else:
            db.add(
                User(
                    username=username,
                    password_hash=auth_service.hash_password(password),
                    role=role,
                )
            )
        db.commit()


def login_as(client: TestClient, username: str, password: str) -> str:
    """Log in via the API; returns the csrf token (cookies are set on the client)."""
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["csrf"]


def as_user(client: TestClient, role: str) -> str:
    """Create + log in a user of the given role. Returns CSRF token."""
    username = f"{role}_user"
    password = "correct-horse-battery-staple"
    create_user(username, password, role)
    return login_as(client, username, password)
