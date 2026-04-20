from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.models import Engagement
from secops.mode_profiles import MODE_PROFILES
from secops.schemas import EngagementCreate, EngagementRead
from secops.security import require_csrf, require_user


router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"], dependencies=[Depends(require_user("operator")), Depends(require_csrf)])


@router.post("", response_model=EngagementRead)
def create_engagement(payload: EngagementCreate, db: Session = Depends(get_db)) -> Engagement:
    if payload.mode not in MODE_PROFILES:
        raise HTTPException(status_code=400, detail=f"Unknown mode: {payload.mode}")
    engagement = Engagement(
        name=payload.name,
        mode=payload.mode,
        target=payload.target,
        ruleset=payload.ruleset or MODE_PROFILES[payload.mode].ruleset,
        status="active",
        notes=payload.notes,
        tags=payload.tags,
        metadata_json=payload.metadata,
    )
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    return engagement


@router.get("", response_model=list[EngagementRead])
def list_engagements(db: Session = Depends(get_db)) -> list[Engagement]:
    return db.query(Engagement).order_by(Engagement.created_at.desc()).all()


@router.get("/{engagement_id}", response_model=EngagementRead)
def get_engagement(engagement_id: str, db: Session = Depends(get_db)) -> Engagement:
    engagement = db.get(Engagement, engagement_id)
    if engagement is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement
