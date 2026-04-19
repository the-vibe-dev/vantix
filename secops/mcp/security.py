from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from starlette.responses import JSONResponse

from secops.config import settings


class MCPAuthAndOriginMiddleware:
    def __init__(self, app: Callable[..., Awaitable[Any]]) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Awaitable[Any]], send: Callable[..., Awaitable[Any]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        origin = headers.get("origin")
        if origin and not self._origin_allowed(origin):
            await JSONResponse({"detail": "Origin not allowed"}, status_code=403)(scope, receive, send)
            return
        if settings.cve_mcp_require_token:
            expected = f"Bearer {settings.api_token}"
            if not settings.api_token or headers.get("authorization") != expected:
                await JSONResponse({"detail": "Missing or invalid MCP bearer token"}, status_code=401)(scope, receive, send)
                return
        await self.app(scope, receive, send)

    def _origin_allowed(self, origin: str) -> bool:
        return any(origin == allowed or origin.startswith(f"{allowed}:") for allowed in settings.cve_mcp_allowed_origins)
