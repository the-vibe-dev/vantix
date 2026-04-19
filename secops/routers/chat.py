from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.schemas import ChatCreate, ChatResponse
from secops.security import require_api_token
from secops.services.execution import execution_manager
from secops.services.vantix import VantixChatService

router = APIRouter(prefix="/api/v1/chat", tags=["chat"], dependencies=[Depends(require_api_token)])


@router.post("", response_model=ChatResponse)
def submit_chat(payload: ChatCreate, db: Session = Depends(get_db)) -> dict:
    try:
        run, message, started, scheduler_status = VantixChatService(db).submit(
            message=payload.message,
            run_id=payload.run_id,
            mode=payload.mode,
            target=payload.target,
            metadata=payload.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    execution_message = execution_manager.start(run.id) if started else "Existing run guidance stored"
    return {"run": run, "message": message, "started": started, "scheduler_status": f"{scheduler_status}; {execution_message}"}
