from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from secops.schemas import ToolInstallCreate, ToolInstallResultRead, ToolStatusRead
from secops.security import require_api_token
from secops.services.tools import ToolService

router = APIRouter(prefix="/api/v1/tools", tags=["tools"], dependencies=[Depends(require_api_token)])


@router.get("", response_model=list[ToolStatusRead])
def list_tools(suite: str = Query(default="")) -> list[dict]:
    return ToolService().list_tools(suite=suite or None)


@router.get("/suites")
def list_tool_suites() -> dict:
    return ToolService().suites()


@router.get("/install/history")
def install_history(limit: int = Query(default=100, ge=1, le=500)) -> list[dict]:
    return ToolService().install_history(limit=limit)


@router.post("/install", response_model=list[ToolInstallResultRead])
def install_tools(payload: ToolInstallCreate) -> list[dict]:
    service = ToolService()
    tool_ids = list(payload.tool_ids)
    if payload.suite:
        suite = service.suites().get(payload.suite)
        if suite is None:
            raise HTTPException(status_code=404, detail="Unknown tool suite")
        tool_ids = [*tool_ids, *suite.get("tools", [])]
    tool_ids = sorted(set(filter(None, tool_ids)))
    if not tool_ids:
        raise HTTPException(status_code=400, detail="Specify tool_ids or suite")
    try:
        return service.install_tools(tool_ids, apply=payload.apply)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
