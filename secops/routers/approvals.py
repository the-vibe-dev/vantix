from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.models import ApprovalRequest, RunMessage, WorkspaceRun
from secops.schemas import ApprovalDecision, ApprovalRead
from secops.security import require_csrf, require_user
from secops.services.events import RunEventService
from secops.services.execution import execution_manager
from secops.services.vantix import VantixScheduler


router = APIRouter(prefix="/api/v1/approvals", tags=["approvals"], dependencies=[Depends(require_user("operator")), Depends(require_csrf)])
events = RunEventService()

def _action_kind_from_reason(reason: str) -> str:
    normalized = (reason or "").strip().lower()
    if normalized.endswith("-policy"):
        return normalized[:-7]
    return ""


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
    if approval.status == "approved":
        return approval
    if approval.status == "rejected":
        raise HTTPException(status_code=409, detail="Approval was already rejected")
    approval.status = "approved"
    approval.response_note = payload.note
    run = db.get(WorkspaceRun, approval.run_id)
    if run is not None:
        action_kind = _action_kind_from_reason(approval.reason)
        if action_kind:
            config = dict(run.config_json or {})
            grants = dict(config.get("approval_grants") or {})
            grants[action_kind] = int(grants.get(action_kind, 0) or 0) + 1
            config["approval_grants"] = grants
            persistent = dict(config.get("approval_grants_persistent") or {})
            if action_kind in {"scope", "recon_high_noise"}:
                persistent[action_kind] = True
            if persistent:
                config["approval_grants_persistent"] = persistent
            if action_kind == "scope":
                scope_overrides = dict(config.get("scope_overrides") or {})
                target = str((approval.metadata_json or {}).get("target") or run.target or "").strip()
                if target:
                    scope_overrides[target] = True
                    config["scope_overrides"] = scope_overrides
            run.config_json = config
        sibling_pending = (
            db.query(ApprovalRequest)
            .filter(
                ApprovalRequest.run_id == approval.run_id,
                ApprovalRequest.id != approval.id,
                ApprovalRequest.reason == approval.reason,
                ApprovalRequest.status == "pending",
            )
            .all()
        )
        for item in sibling_pending:
            item.status = "approved"
            item.response_note = f"Auto-resolved by approval {approval.id}"
        if approval.reason == "quick-scan-gate":
            config = dict(run.config_json or {})
            config["scan_profile"] = "full"
            config["quick_scan_gate_pending"] = False
            run.config_json = config
            VantixScheduler().expand_after_quick_scan_approval(db, run)
        if run.status in {"blocked", "queued"}:
            run.status = "queued"
        db.add(
            RunMessage(
                run_id=approval.run_id,
                role="system",
                author="System",
                content=f"Approval granted: {approval.title}. Resuming execution.",
                metadata_json={"approval_id": approval.id, "approval_reason": approval.reason},
            )
        )
        events.emit(
            db,
            approval.run_id,
            "approval",
            f"Approval granted: {approval.title}",
            payload={"approval_id": approval.id, "reason": approval.reason},
        )
    db.commit()
    db.refresh(approval)
    if run is not None:
        execution_manager.start(approval.run_id)
    return approval


@router.post("/{approval_id}/reject", response_model=ApprovalRead)
def reject(approval_id: str, payload: ApprovalDecision, db: Session = Depends(get_db)) -> ApprovalRequest:
    approval = db.get(ApprovalRequest, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.status == "rejected":
        return approval
    if approval.status == "approved":
        raise HTTPException(status_code=409, detail="Approval was already approved")
    approval.status = "rejected"
    approval.response_note = payload.note
    run = db.get(WorkspaceRun, approval.run_id)
    if run is not None:
        run.status = "blocked"
        db.add(
            RunMessage(
                run_id=approval.run_id,
                role="system",
                author="System",
                content=f"Approval rejected: {approval.title}. Run remains blocked.",
                metadata_json={"approval_id": approval.id, "approval_reason": approval.reason},
            )
        )
        events.emit(
            db,
            approval.run_id,
            "approval",
            f"Approval rejected: {approval.title}",
            level="warning",
            payload={"approval_id": approval.id, "reason": approval.reason},
        )
    db.commit()
    db.refresh(approval)
    return approval
