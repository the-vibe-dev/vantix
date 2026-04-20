from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from secops.security import require_api_token
from secops.services.source_intake import SourceIntakeService


router = APIRouter(prefix="/api/v1/sources", tags=["sources"], dependencies=[Depends(require_api_token)])


@router.post("/uploads")
def stage_source_upload(file: UploadFile = File(...)) -> dict:
    try:
        return SourceIntakeService().stage_upload(file)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

