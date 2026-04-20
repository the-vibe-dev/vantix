from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Response
from sqlalchemy import text

from secops.db import SessionLocal


router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness — process is up."""
    return {"status": "ok"}


@router.get("/readyz")
def readyz(response: Response) -> dict[str, object]:
    """Readiness — DB reachable + at least one fresh worker heartbeat."""
    db_ok = False
    worker_ok = False
    details: dict[str, object] = {}
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
            db_ok = True
            from secops.models import WorkerRuntimeStatus

            latest = (
                db.query(WorkerRuntimeStatus)
                .order_by(WorkerRuntimeStatus.heartbeat_at.desc())
                .first()
            )
            if latest is not None:
                heartbeat_at = latest.heartbeat_at
                if heartbeat_at.tzinfo is None:
                    heartbeat_at = heartbeat_at.replace(tzinfo=timezone.utc)
                fresh = (datetime.now(timezone.utc) - heartbeat_at) < timedelta(seconds=120)
                worker_ok = fresh
                details["latest_heartbeat_at"] = heartbeat_at.isoformat()
                details["worker_id"] = latest.worker_id
    except Exception as exc:  # noqa: BLE001
        details["error"] = str(exc)
    ready = db_ok and worker_ok
    if not ready:
        response.status_code = 503
    return {
        "ready": ready,
        "db_ok": db_ok,
        "worker_ok": worker_ok,
        **details,
    }
