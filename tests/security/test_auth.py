"""PRA-001 / PRA-014 regression: empty token fails closed; wrong token rejected."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_security_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"
os.environ.setdefault("SECOPS_DEV_MODE", "0")

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
    }
    yield
    for key, value in originals.items():
        _set(key, value)


def test_empty_token_non_dev_rejects_all_requests() -> None:
    _reset_db()
    _set("api_token", "")
    _set("dev_mode", False)
    client = TestClient(create_app())

    # Protected routes must refuse in this configuration.
    resp = client.get("/api/v1/runs")
    assert resp.status_code == 503
    assert "SECOPS_API_TOKEN" in resp.json()["detail"]


def test_wrong_token_rejected() -> None:
    _reset_db()
    _set("api_token", "the-real-token")
    _set("dev_mode", False)
    client = TestClient(create_app())

    resp = client.get("/api/v1/runs", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401


def test_correct_token_accepted() -> None:
    _reset_db()
    _set("api_token", "right-token")
    _set("dev_mode", False)
    client = TestClient(create_app())

    resp = client.get("/api/v1/runs", headers={"Authorization": "Bearer right-token"})
    assert resp.status_code == 200


def test_dev_mode_allows_no_token() -> None:
    _reset_db()
    _set("api_token", "")
    _set("dev_mode", True)
    client = TestClient(create_app())

    resp = client.get("/api/v1/runs")
    assert resp.status_code == 200


def test_missing_credentials_rejected() -> None:
    _reset_db()
    _set("api_token", "prod-token")
    _set("dev_mode", False)
    client = TestClient(create_app())

    resp = client.get("/api/v1/runs")
    assert resp.status_code == 401
