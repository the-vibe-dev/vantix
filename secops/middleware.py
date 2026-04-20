"""Lightweight middleware: request-id, rate limit, audit log.

No external deps. Rate limiter is in-process only — fine for a single API
process; deploy Redis-backed limiter if you scale out.
"""
from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


_logger = logging.getLogger("secops.middleware")


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            _logger.exception("unhandled exception request_id=%s path=%s", request_id, request.url.path)
            return JSONResponse(
                status_code=500,
                content={"detail": "internal error", "request_id": request_id},
                headers={"x-request-id": request_id},
            )
        response.headers["x-request-id"] = request_id
        return response


# Routes that are privileged / state-changing / worth rate-limiting.
# (method, path_suffix) — match by method + endswith.
_LIMITED_SUFFIXES = (
    "/start",
    "/pause",
    "/cancel",
    "/retry",
    "/replan",
    "/resume",
    "/approve",
    "/reject",
    "/providers",
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple fixed-window-ish sliding counter per (remote_addr, route-class).

    Defaults: 30 requests / 60 s on limited routes. Non-limited routes pass.
    """

    def __init__(self, app, *, max_requests: int = 30, window_seconds: int = 60) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def _limited(self, method: str, path: str) -> bool:
        if method not in {"POST", "PUT", "DELETE"}:
            return False
        return any(path.endswith(suffix) for suffix in _LIMITED_SUFFIXES)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method.upper()
        if self._limited(method, path):
            remote = request.client.host if request.client else "-"
            key = (remote, path)
            now = time.time()
            bucket = self._hits[key]
            cutoff = now - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                request_id = getattr(request.state, "request_id", "")
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "rate limit exceeded",
                        "request_id": request_id,
                        "retry_after_seconds": self.window,
                    },
                    headers={"Retry-After": str(self.window)},
                )
            bucket.append(now)
        return await call_next(request)


_AUDITED_PREFIXES = (
    "/api/v1/runs/",       # start/pause/cancel/retry/replan
    "/api/v1/approvals/",
    "/api/v1/providers",
)

_AUDIT_METHODS = {"POST", "PUT", "DELETE"}


class AuditMiddleware(BaseHTTPMiddleware):
    """Persist an AuditLog row for each privileged state-change."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if request.method.upper() in _AUDIT_METHODS and any(request.url.path.startswith(p) for p in _AUDITED_PREFIXES):
            try:
                from secops.db import SessionLocal
                from secops.models import AuditLog

                authz = request.headers.get("authorization") or ""
                actor = "anonymous"
                if authz.lower().startswith("bearer "):
                    tok = authz.split(" ", 1)[1].strip()
                    actor = f"token:{tok[:4]}...{tok[-2:]}" if len(tok) >= 8 else "token:***"
                with SessionLocal() as db:
                    db.add(
                        AuditLog(
                            request_id=getattr(request.state, "request_id", ""),
                            actor=actor,
                            method=request.method.upper(),
                            route=request.url.path,
                            verdict=str(response.status_code),
                            remote_addr=request.client.host if request.client else "",
                            payload_json={"query": dict(request.query_params)},
                        )
                    )
                    db.commit()
            except Exception:  # noqa: BLE001
                _logger.exception("audit log write failed path=%s", request.url.path)
        return response
