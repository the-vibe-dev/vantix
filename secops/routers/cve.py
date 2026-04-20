from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.schemas import CVESearchResponse
from secops.security import require_api_token
from secops.services.intel_sources import adapter_for, available_sources
from secops.services.cve_search import CVESearchService
from secops.services.vuln_intel import VulnIntelService


router = APIRouter(prefix="/api/v1/cve", tags=["cve"], dependencies=[Depends(require_api_token)])


@router.get("/search", response_model=CVESearchResponse)
def search_cves(
    vendor: str = Query(...),
    product: str = Query(...),
    live_on_miss: bool = Query(default=True),
    source: list[str] | None = Query(default=None),
    live_limit: int = Query(default=200, ge=1, le=1000),
    always_search_external: bool = Query(default=False),
) -> dict:
    return CVESearchService().search(
        vendor=vendor,
        product=product,
        live_on_miss=live_on_miss,
        live_sources=source,
        live_limit=live_limit,
        always_search_external=always_search_external,
    )


@router.get("/intel")
def get_cve_intel(cve_id: str = Query(...), db: Session = Depends(get_db)) -> dict:
    return {"cve_id": cve_id.upper(), "intel": VulnIntelService(db).for_cve(cve_id)}


@router.get("/intel/search")
def search_cve_intel(
    q: str = Query(..., min_length=2),
    limit: int = Query(default=100, ge=1, le=500),
    source: list[str] | None = Query(default=None),
    live_on_miss: bool = Query(default=True),
    live_limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> dict:
    service = VulnIntelService(db)
    intel = service.search(q, limit=limit, sources=source)
    live_meta = {
        "attempted": False,
        "enabled": live_on_miss,
        "sources": source or [],
        "fetched_records": 0,
        "upserted": 0,
        "errors": [],
    }
    if intel or not live_on_miss:
        return {"query": q, "limit": limit, "sources": source or [], "intel": intel, "live": live_meta}

    target_sources = source or available_sources(include_optional=False)
    live_meta["attempted"] = True
    live_meta["sources"] = target_sources
    any_changes = False

    for source_name in target_sources:
        try:
            adapter = adapter_for(source_name)
        except Exception as exc:  # noqa: BLE001
            live_meta["errors"].append(f"{source_name}: {exc}")
            continue

        result = adapter.fetch_since({"limit": live_limit})
        if result.error:
            live_meta["errors"].append(f"{source_name}: {result.error}")
            continue

        filtered = service.filter_records_by_term(result.records, q)
        if not filtered:
            continue

        counts = service.upsert_records(filtered, commit=False)
        live_meta["fetched_records"] += len(filtered)
        live_meta["upserted"] += int(counts.get("upserted", 0) or 0)
        any_changes = any_changes or bool(filtered)

    if any_changes:
        db.commit()
    intel = service.search(q, limit=limit, sources=source)
    return {"query": q, "limit": limit, "sources": source or [], "intel": intel, "live": live_meta}


@router.get("/intel/recent")
def get_recent_cve_intel(days: int = Query(default=7, ge=1, le=120), limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)) -> dict:
    return {"days": days, "limit": limit, "intel": VulnIntelService(db).recent(days=days, limit=limit)}


@router.get("/intel/sources")
def list_intel_sources(include_optional: bool = Query(default=True)) -> dict:
    return {"sources": available_sources(include_optional=include_optional)}


@router.post("/intel/update")
def update_cve_intel(
    source: str = Query(default="cisa_kev"),
    dry_run: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict:
    adapter = adapter_for(source)
    result = adapter.fetch_since({})
    payload = {
        "source": result.source,
        "fetched": len(result.records),
        "cursor": result.cursor,
        "error": result.error,
        "dry_run": dry_run,
    }
    if dry_run or result.error:
        return payload
    service = VulnIntelService(db)
    counts = service.upsert_records(result.records)
    return {**payload, "db": counts}
