from __future__ import annotations

import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

from passlib.exc import MissingBackendError

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_auth_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"
os.environ["SECOPS_RUNTIME_ROOT"] = str(Path(tempfile.gettempdir()) / f"secops_auth_runtime_{os.getpid()}")

from secops.db import Base, SessionLocal, engine
from secops.models import User
from secops.services import auth_service


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_hash_password_falls_back_when_argon2_backend_missing(monkeypatch) -> None:
    monkeypatch.setattr(auth_service.argon2, "hash", lambda _: (_ for _ in ()).throw(MissingBackendError("argon2 missing")))
    hashed = auth_service.hash_password("secret-123")
    assert hashed.startswith("$pbkdf2-sha256$")
    assert auth_service.verify_password("secret-123", hashed)


def test_bootstrap_users_if_needed_creates_admin_and_extras(monkeypatch) -> None:
    reset_db()
    fake_settings = SimpleNamespace(
        admin_username="admin",
        admin_password="AdminPass!234",
        bootstrap_users="operator1:OpPass!234:operator,viewer1:ViewPass!234:viewer",
    )
    monkeypatch.setattr(auth_service, "settings", fake_settings)
    with SessionLocal() as db:
        created = auth_service.bootstrap_users_if_needed(db)
        db.commit()
        rows = db.query(User).order_by(User.username.asc()).all()
    assert len(created) == 3
    assert [row.username for row in rows] == ["admin", "operator1", "viewer1"]
    assert [row.role for row in rows] == ["admin", "operator", "viewer"]


def test_bootstrap_users_if_needed_noop_when_users_exist(monkeypatch) -> None:
    reset_db()
    fake_settings = SimpleNamespace(
        admin_username="admin",
        admin_password="AdminPass!234",
        bootstrap_users="operator1:OpPass!234:operator",
    )
    monkeypatch.setattr(auth_service, "settings", fake_settings)
    with SessionLocal() as db:
        db.add(User(username="existing", password_hash=auth_service.hash_password("pw"), role="admin"))
        db.commit()
        created = auth_service.bootstrap_users_if_needed(db)
    assert created == []
