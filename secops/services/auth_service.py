from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from passlib.hash import argon2
from passlib.hash import pbkdf2_sha256
from passlib.exc import MissingBackendError
from sqlalchemy.orm import Session

from secops.config import settings
from secops.models import User, UserSession


ROLES_ORDER = {"viewer": 0, "operator": 1, "admin": 2}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(plaintext: str) -> str:
    try:
        return argon2.hash(plaintext)
    except MissingBackendError:
        # Keep auth operational when argon2 backend is unavailable (common on
        # some local Python builds) and store a strong hash format.
        return pbkdf2_sha256.hash(plaintext)


def verify_password(plaintext: str, stored_hash: str) -> bool:
    try:
        if (stored_hash or "").startswith("$argon2"):
            return argon2.verify(plaintext, stored_hash)
        if (stored_hash or "").startswith("$pbkdf2-sha256"):
            return pbkdf2_sha256.verify(plaintext, stored_hash)
        return False
    except Exception:
        return False


def role_at_least(user_role: str, required: str) -> bool:
    return ROLES_ORDER.get(user_role, -1) >= ROLES_ORDER.get(required, 99)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_session(
    db: Session,
    user: User,
    *,
    remote_addr: str = "",
    user_agent: str = "",
    ttl_hours: int | None = None,
) -> tuple[str, str, UserSession]:
    """Returns (session_raw_token, csrf_raw_token, UserSession row)."""
    ttl = ttl_hours if ttl_hours is not None else settings.session_ttl_hours
    raw_session = secrets.token_urlsafe(32)
    raw_csrf = secrets.token_urlsafe(32)
    row = UserSession(
        user_id=user.id,
        token_hash=_hash_token(raw_session),
        csrf_token=raw_csrf,
        expires_at=utcnow() + timedelta(hours=ttl),
        remote_addr=remote_addr[:64],
        user_agent=user_agent[:255],
    )
    db.add(row)
    user.last_login_at = utcnow()
    db.flush()
    return raw_session, raw_csrf, row


def lookup_session(db: Session, raw_token: str) -> tuple[User, UserSession] | None:
    if not raw_token:
        return None
    token_hash = _hash_token(raw_token)
    session_row = db.query(UserSession).filter(UserSession.token_hash == token_hash).first()
    if session_row is None or session_row.revoked:
        return None
    expires_at = session_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= utcnow():
        return None
    user = db.get(User, session_row.user_id)
    if user is None or user.disabled:
        return None
    session_row.last_seen_at = utcnow()
    return user, session_row


def revoke_session(db: Session, session_row: UserSession) -> None:
    session_row.revoked = True


def revoke_all_for_user(db: Session, user_id: str) -> int:
    n = 0
    for row in db.query(UserSession).filter(UserSession.user_id == user_id, UserSession.revoked.is_(False)).all():
        row.revoked = True
        n += 1
    return n


def bootstrap_admin_if_needed(db: Session) -> User | None:
    """Create an admin user from SECOPS_ADMIN_USERNAME/PASSWORD if the users table is empty."""
    if db.query(User).count() > 0:
        return None
    username = settings.admin_username
    password = settings.admin_password
    if not username or not password:
        return None
    user = User(
        username=username,
        password_hash=hash_password(password),
        role="admin",
    )
    db.add(user)
    db.flush()
    return user


def _parse_bootstrap_users(raw: str) -> list[dict[str, str]]:
    text = str(raw or "").strip()
    if not text:
        return []
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    # JSON list form: [{"username":"u","password":"p","role":"operator"}]
    if text.startswith("["):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = []
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                username = str(item.get("username") or "").strip()
                password = str(item.get("password") or "")
                role = str(item.get("role") or "operator").strip().lower()
                if not username or not password or username in seen:
                    continue
                if role not in {"viewer", "operator", "admin"}:
                    role = "operator"
                seen.add(username)
                out.append({"username": username, "password": password, "role": role})
        return out
    # CSV form: username:password:role,username2:password2:role2
    for chunk in text.split(","):
        item = chunk.strip()
        if not item:
            continue
        parts = item.split(":")
        if len(parts) < 2:
            continue
        username = parts[0].strip()
        password = parts[1]
        role = (parts[2].strip().lower() if len(parts) >= 3 else "operator")
        if not username or not password or username in seen:
            continue
        if role not in {"viewer", "operator", "admin"}:
            role = "operator"
        seen.add(username)
        out.append({"username": username, "password": password, "role": role})
    return out


def bootstrap_users_if_needed(db: Session) -> list[User]:
    """Create first-boot users from SECOPS_ADMIN_* and optional SECOPS_BOOTSTRAP_USERS when users table is empty."""
    if db.query(User).count() > 0:
        return []
    rows: list[dict[str, Any]] = []
    if settings.admin_username and settings.admin_password:
        rows.append({"username": settings.admin_username, "password": settings.admin_password, "role": "admin"})
    rows.extend(_parse_bootstrap_users(settings.bootstrap_users))
    created: list[User] = []
    seen: set[str] = set()
    for row in rows:
        username = str(row.get("username") or "").strip()
        password = str(row.get("password") or "")
        role = str(row.get("role") or "operator").lower()
        if not username or not password or username in seen:
            continue
        if role not in {"viewer", "operator", "admin"}:
            role = "operator"
        user = User(username=username, password_hash=hash_password(password), role=role)
        db.add(user)
        db.flush()
        created.append(user)
        seen.add(username)
    return created
