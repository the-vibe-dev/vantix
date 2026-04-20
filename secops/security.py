from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from secops.config import settings
from secops.db import SessionLocal
from secops.services import auth_service


SESSION_COOKIE = "vantix_session"
CSRF_COOKIE = "vantix_csrf"
CSRF_HEADER = "x-csrf-token"
MUTATING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthContext:
    kind: str  # "user" or "service"
    username: str
    role: str


def _reject(status_code: int, detail: str) -> None:
    raise HTTPException(status_code=status_code, detail=detail)


def _service_token_ok(credentials: HTTPAuthorizationCredentials | None) -> bool:
    if not settings.service_token_enabled:
        return False
    expected = settings.api_token
    if not expected or credentials is None:
        return False
    return hmac.compare_digest(credentials.credentials, expected)


def require_api_token(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
    """Legacy service-token auth. Fails closed unless SECOPS_SERVICE_TOKEN_ENABLED=1."""
    if settings.dev_mode:
        return
    if not settings.service_token_enabled:
        _reject(status.HTTP_401_UNAUTHORIZED, "Service token auth disabled; use /api/v1/auth/login")
    expected = settings.api_token
    if not expected:
        _reject(status.HTTP_503_SERVICE_UNAVAILABLE, "Server misconfigured: SECOPS_API_TOKEN is not set")
    if credentials is None or not hmac.compare_digest(credentials.credentials, expected):
        _reject(status.HTTP_401_UNAUTHORIZED, "Invalid API token")


def require_user(min_role: str = "operator") -> Callable[..., AuthContext]:
    """FastAPI dependency factory. Resolves the caller to either a logged-in user or a service token."""

    def _dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> AuthContext:
        if settings.dev_mode:
            ctx = AuthContext(kind="user", username="dev", role="admin")
            request.state.auth = ctx
            return ctx

        if _service_token_ok(credentials):
            ctx = AuthContext(kind="service", username="service", role="admin")
            request.state.auth = ctx
            return ctx

        raw = request.cookies.get(SESSION_COOKIE, "")
        if not raw:
            _reject(status.HTTP_401_UNAUTHORIZED, "Not authenticated")

        with SessionLocal() as db:
            found = auth_service.lookup_session(db, raw)
            if found is None:
                _reject(status.HTTP_401_UNAUTHORIZED, "Session invalid or expired")
            user, session = found
            if not auth_service.role_at_least(user.role, min_role):
                _reject(status.HTTP_403_FORBIDDEN, f"Requires role: {min_role}")

            ctx = AuthContext(kind="user", username=user.username, role=user.role)
            request.state.auth = ctx
            request.state.csrf_token = session.csrf_token
            db.commit()  # persist last_seen_at bump
            return ctx

        # unreachable
        _reject(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
        return AuthContext(kind="user", username="", role="")

    return _dependency


def require_csrf(request: Request) -> None:
    """Enforce double-submit CSRF for cookie-auth mutating requests.

    Skipped when:
    - request method is non-mutating
    - caller authenticated via service token (no cookie)
    - dev_mode is on
    """
    if request.method.upper() not in MUTATING_METHODS:
        return
    if settings.dev_mode:
        return
    auth = getattr(request.state, "auth", None)
    if auth is not None and auth.kind == "service":
        return
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    header_token = request.headers.get(CSRF_HEADER, "")
    if not cookie_token or not header_token:
        _reject(status.HTTP_403_FORBIDDEN, "Missing CSRF token")
    if not hmac.compare_digest(cookie_token, header_token):
        _reject(status.HTTP_403_FORBIDDEN, "Invalid CSRF token")
