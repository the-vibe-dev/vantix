from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.models import Action, Task
from secops.schemas import ActionRead, TaskRead
from secops.security import require_csrf, require_user


router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"], dependencies=[Depends(require_user("operator")), Depends(require_csrf)])


@router.get("/{task_id}", response_model=TaskRead)
def get_task(task_id: str, db: Session = Depends(get_db)) -> Task:
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.get("/{task_id}/actions", response_model=list[ActionRead])
def list_task_actions(task_id: str, db: Session = Depends(get_db)) -> list[Action]:
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return db.query(Action).filter(Action.task_id == task_id).all()
