from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from secops.schemas import SkillPackCreate, SkillPackRead, SkillPackUpdate, SkillRegistryReloadRead
from secops.security import require_csrf, require_user
from secops.services.skills import SkillRegistry


router = APIRouter(prefix="/api/v1/skills", tags=["skills"], dependencies=[Depends(require_user("viewer")), Depends(require_csrf)])


@router.get("", response_model=list[SkillPackRead])
def list_skill_packs() -> list[dict]:
    return [pack.public() for pack in SkillRegistry().all()]


@router.post("", response_model=SkillPackRead)
def create_skill_pack(payload: SkillPackCreate) -> dict:
    registry = SkillRegistry()
    try:
        return registry.create_local(payload.model_dump()).public()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/{skill_id}", response_model=SkillPackRead)
def update_skill_pack(skill_id: str, payload: SkillPackUpdate) -> dict:
    registry = SkillRegistry()
    try:
        return registry.update_local(skill_id, {key: value for key, value in payload.model_dump().items() if value is not None}).public()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{skill_id}", status_code=204)
def delete_skill_pack(skill_id: str) -> None:
    registry = SkillRegistry()
    try:
        registry.delete_local(skill_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/reload", response_model=SkillRegistryReloadRead)
def reload_skill_packs() -> dict:
    registry = SkillRegistry()
    skills = [pack.public() for pack in registry.reload()]
    return {"count": len(skills), "skills": skills}
