from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from secops.config import settings


bearer = HTTPBearer(auto_error=False)


def require_api_token(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
    if not settings.api_token:
        return
    if credentials is None or credentials.credentials != settings.api_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API token")
