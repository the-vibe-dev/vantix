"""PRA-013: password hashing + session lifecycle unit tests."""
from __future__ import annotations

from tests.security._helpers import isolated_db_env

isolated_db_env()

from datetime import timedelta  # noqa: E402

from secops.db import SessionLocal  # noqa: E402
from secops.models import User  # noqa: E402
from secops.services import auth_service  # noqa: E402
from tests.security._helpers import reset_db  # noqa: E402


def _make_user(username: str = "alice", role: str = "operator") -> User:
    reset_db()
    with SessionLocal() as db:
        user = User(
            username=username,
            password_hash=auth_service.hash_password("s3cret!"),
            role=role,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


def test_password_hash_roundtrip() -> None:
    _make_user()
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "alice").first()
        assert user is not None
        assert user.password_hash != "s3cret!"
        assert user.password_hash.startswith("$argon2")
        assert auth_service.verify_password("s3cret!", user.password_hash)
        assert not auth_service.verify_password("wrong", user.password_hash)


def test_session_create_lookup_roundtrip() -> None:
    _make_user()
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "alice").first()
        raw_session, raw_csrf, row = auth_service.create_session(db, user)
        db.commit()
        assert raw_session and raw_csrf and row.token_hash != raw_session

        found = auth_service.lookup_session(db, raw_session)
        assert found is not None
        user2, _ = found
        assert user2.username == "alice"


def test_session_expired_rejected() -> None:
    _make_user()
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "alice").first()
        raw_session, _, row = auth_service.create_session(db, user, ttl_hours=1)
        row.expires_at = auth_service.utcnow() - timedelta(hours=1)
        db.commit()
        assert auth_service.lookup_session(db, raw_session) is None


def test_session_revoked_rejected() -> None:
    _make_user()
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "alice").first()
        raw_session, _, row = auth_service.create_session(db, user)
        auth_service.revoke_session(db, row)
        db.commit()
        assert auth_service.lookup_session(db, raw_session) is None


def test_disabled_user_session_rejected() -> None:
    _make_user()
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "alice").first()
        raw_session, _, _ = auth_service.create_session(db, user)
        user.disabled = True
        db.commit()
        assert auth_service.lookup_session(db, raw_session) is None


def test_role_at_least() -> None:
    assert auth_service.role_at_least("admin", "viewer")
    assert auth_service.role_at_least("operator", "operator")
    assert not auth_service.role_at_least("viewer", "operator")
    assert not auth_service.role_at_least("operator", "admin")
