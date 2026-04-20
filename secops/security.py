from __future__ import annotations

import hmac

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from secops.config import settings


bearer = HTTPBearer(auto_error=False)


def require_api_token(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
    expected = settings.api_token
    if not expected:
        if settings.dev_mode:
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server misconfigured: SECOPS_API_TOKEN is not set",
        )
    if credentials is None or not hmac.compare_digest(credentials.credentials, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API token")
