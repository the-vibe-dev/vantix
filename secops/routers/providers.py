from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.schemas import ProviderConfigCreate, ProviderConfigRead
from secops.security import require_csrf, require_user
from secops.services.providers import ProviderService

router = APIRouter(prefix="/api/v1/providers", tags=["providers"], dependencies=[Depends(require_user("admin")), Depends(require_csrf)])


@router.get("", response_model=list[ProviderConfigRead])
def list_providers(db: Session = Depends(get_db)) -> list[dict]:
    return ProviderService(db).list()


@router.post("", response_model=ProviderConfigRead)
def upsert_provider(payload: ProviderConfigCreate, db: Session = Depends(get_db)) -> dict:
    service = ProviderService(db)
    try:
        row = service.upsert(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    db.refresh(row)
    return service.to_read(row)


@router.get("/{provider_id}", response_model=ProviderConfigRead)
def get_provider(provider_id: str, db: Session = Depends(get_db)) -> dict:
    service = ProviderService(db)
    row = service.get(provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Provider not found")
    return service.to_read(row)


@router.delete("/{provider_id}")
def delete_provider(provider_id: str, db: Session = Depends(get_db)) -> dict:
    deleted = ProviderService(db).delete(provider_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Provider not found")
    db.commit()
    return {"ok": True}


@router.post("/{provider_id}/test")
def test_provider(provider_id: str, db: Session = Depends(get_db)) -> dict:
    row = ProviderService(db).get(provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Provider not found")
    return {"ok": True, "provider_id": provider_id, "mode": "dry-run", "message": "Provider record is configured; live model calls are not performed by default."}
