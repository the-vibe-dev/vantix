from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.models import ApprovalRequest
from secops.schemas import ApprovalDecision, ApprovalRead
from secops.security import require_api_token


router = APIRouter(prefix="/api/v1/approvals", tags=["approvals"], dependencies=[Depends(require_api_token)])


@router.get("/{approval_id}", response_model=ApprovalRead)
def get_approval(approval_id: str, db: Session = Depends(get_db)) -> ApprovalRequest:
    approval = db.get(ApprovalRequest, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return approval


@router.post("/{approval_id}/approve", response_model=ApprovalRead)
def approve(approval_id: str, payload: ApprovalDecision, db: Session = Depends(get_db)) -> ApprovalRequest:
    approval = db.get(ApprovalRequest, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    approval.status = "approved"
    approval.response_note = payload.note
    db.commit()
    db.refresh(approval)
    return approval


@router.post("/{approval_id}/reject", response_model=ApprovalRead)
def reject(approval_id: str, payload: ApprovalDecision, db: Session = Depends(get_db)) -> ApprovalRequest:
    approval = db.get(ApprovalRequest, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    approval.status = "rejected"
    approval.response_note = payload.note
    db.commit()
    db.refresh(approval)
    return approval
