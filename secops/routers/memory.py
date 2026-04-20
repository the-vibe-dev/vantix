from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.schemas import DenseMemoryCreate, DenseMemoryReceipt, MemoryHealthRead
from secops.security import require_csrf, require_user
from secops.services.learning import LearningService
from secops.services.memory_writer import DenseMemoryRecord, MemoryWriteService


router = APIRouter(prefix="/api/v1/memory", tags=["memory"], dependencies=[Depends(require_user("viewer")), Depends(require_csrf)])


@router.get("/search")
def search_memory(q: str = Query(..., min_length=2), limit: int = Query(default=25, ge=1, le=100)) -> list[dict]:
    return LearningService().search_memory(query=q, limit=limit)


@router.get("/review-queue")
def review_queue() -> list[dict]:
    return LearningService().review_queue()


@router.post("/checkpoint", response_model=DenseMemoryReceipt)
def write_checkpoint(payload: DenseMemoryCreate, db: Session = Depends(get_db)) -> dict:
    record = DenseMemoryRecord(**{**payload.model_dump(), "mode": payload.mode or "checkpoint"})
    return MemoryWriteService().write(record, db=db)


@router.post("/handoff", response_model=DenseMemoryReceipt)
def write_handoff(payload: DenseMemoryCreate, db: Session = Depends(get_db)) -> dict:
    record = DenseMemoryRecord(**{**payload.model_dump(), "mode": "handoff"})
    return MemoryWriteService().write(record, db=db)


@router.get("/latest")
def latest_memory() -> dict:
    return MemoryWriteService().latest() or {}


@router.get("/health", response_model=MemoryHealthRead)
def memory_health(stale_minutes: int = Query(default=30, ge=1, le=1440)) -> dict:
    return MemoryWriteService().health(stale_minutes=stale_minutes)
