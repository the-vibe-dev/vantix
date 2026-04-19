from __future__ import annotations

from fastapi import APIRouter, Depends

from secops.mode_profiles import MODE_PROFILES, get_mode_profile
from secops.security import require_api_token


router = APIRouter(prefix="/api/v1/modes", tags=["modes"], dependencies=[Depends(require_api_token)])


@router.get("")
def list_modes() -> list[dict]:
    return [profile.to_dict() for profile in MODE_PROFILES.values()]


@router.get("/{mode_id}")
def get_mode(mode_id: str) -> dict:
    return get_mode_profile(mode_id).to_dict()
