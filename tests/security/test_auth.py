"""PRA-001 / PRA-014 regression: empty token fails closed; wrong token rejected.

These tests cover the legacy service-token path (SECOPS_SERVICE_TOKEN_ENABLED=1).
Cookie-based user auth is covered in test_auth_flow.py.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_security_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"
os.environ.setdefault("SECOPS_DEV_MODE", "0")
os.environ["SECOPS_ENABLE_BACKGROUND_WORKER"] = "0"

import pytest
from fastapi.testclient import TestClient

from secops.app import create_app
from secops.config import settings
from secops.db import Base, engine


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _set(field: str, value) -> None:
    object.__setattr__(settings, field, value)


@pytest.fixture(autouse=True)
def _restore_settings():
    originals = {
        "api_token": settings.api_token,
        "dev_mode": settings.dev_mode,
        "service_token_enabled": settings.service_token_enabled,
        "enable_background_worker": settings.enable_background_worker,
    }
    yield
    for key, value in originals.items():
        _set(key, value)


def test_empty_token_with_service_mode_rejects() -> None:
    _reset_db()
    _set("api_token", "")
    _set("dev_mode", False)
    _set("service_token_enabled", True)
    _set("enable_background_worker", False)
    with TestClient(create_app()) as client:
        resp = client.get("/api/v1/runs")
        assert resp.status_code == 503
        assert "SECOPS_API_TOKEN" in resp.json()["detail"]


def test_service_token_disabled_rejects_bearer() -> None:
    _reset_db()
    _set("api_token", "right-token")
    _set("dev_mode", False)
    _set("service_token_enabled", False)
    _set("enable_background_worker", False)
    with TestClient(create_app()) as client:
        resp = client.get("/api/v1/runs", headers={"Authorization": "Bearer right-token"})
        assert resp.status_code == 401


def test_wrong_token_rejected() -> None:
    _reset_db()
    _set("api_token", "the-real-token")
    _set("dev_mode", False)
    _set("service_token_enabled", True)
    _set("enable_background_worker", False)
    with TestClient(create_app()) as client:
        resp = client.get("/api/v1/runs", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 401


def test_correct_token_accepted() -> None:
    _reset_db()
    _set("api_token", "right-token")
    _set("dev_mode", False)
    _set("service_token_enabled", True)
    _set("enable_background_worker", False)
    with TestClient(create_app()) as client:
        resp = client.get("/api/v1/runs", headers={"Authorization": "Bearer right-token"})
        assert resp.status_code == 200


def test_dev_mode_allows_no_token() -> None:
    _reset_db()
    _set("api_token", "")
    _set("dev_mode", True)
    _set("enable_background_worker", False)
    with TestClient(create_app()) as client:
        resp = client.get("/api/v1/runs")
        assert resp.status_code == 200


def test_missing_credentials_rejected() -> None:
    _reset_db()
    _set("api_token", "prod-token")
    _set("dev_mode", False)
    _set("service_token_enabled", True)
    _set("enable_background_worker", False)
    with TestClient(create_app()) as client:
        resp = client.get("/api/v1/runs")
        assert resp.status_code == 401
