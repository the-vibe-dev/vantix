from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from secops.config import settings
from secops.db import get_db
from secops.security import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    AuthContext,
    require_user,
)
from secops.services import auth_service
from secops.models import User


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    username: str
    role: str


class LoginOut(BaseModel):
    user: UserOut
    csrf: str


def _set_auth_cookies(response: Response, session_token: str, csrf_token: str) -> None:
    max_age = settings.session_ttl_hours * 3600
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=max_age,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


@router.post("/login", response_model=LoginOut)
def login(payload: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> LoginOut:
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or user.disabled or not auth_service.verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    raw_session, raw_csrf, _ = auth_service.create_session(
        db,
        user,
        remote_addr=(request.client.host if request.client else ""),
        user_agent=request.headers.get("user-agent", ""),
    )
    db.commit()
    _set_auth_cookies(response, raw_session, raw_csrf)
    return LoginOut(user=UserOut(username=user.username, role=user.role), csrf=raw_csrf)


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> dict[str, bool]:
    raw = request.cookies.get(SESSION_COOKIE, "")
    if raw:
        found = auth_service.lookup_session(db, raw)
        if found is not None:
            auth_service.revoke_session(db, found[1])
            db.commit()
    _clear_auth_cookies(response)
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(auth: AuthContext = Depends(require_user("viewer"))) -> UserOut:
    return UserOut(username=auth.username, role=auth.role)
