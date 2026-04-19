from __future__ import annotations

from fastapi import APIRouter, Depends

from secops.schemas import SkillPackRead
from secops.security import require_api_token
from secops.services.skills import SkillRegistry


router = APIRouter(prefix="/api/v1/skills", tags=["skills"], dependencies=[Depends(require_api_token)])


@router.get("", response_model=list[SkillPackRead])
def list_skill_packs() -> list[dict]:
    return [pack.public() for pack in SkillRegistry().all()]
