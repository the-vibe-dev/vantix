from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from secops.db import SessionLocal, get_db


router = APIRouter(tags=["health"])


_STALE_HEARTBEAT_SECONDS = 120
_STALE_LEASE_SECONDS = 180


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


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@router.get("/runtime/health")
def runtime_health(db: Session = Depends(get_db)) -> dict[str, object]:
    """Operational snapshot: lease census, heartbeat ages, stale candidates."""
    from secops.models import WorkerLease, WorkerRuntimeStatus

    now = datetime.now(timezone.utc)
    leases = db.query(WorkerLease).all()
    by_state: dict[str, int] = {}
    stale_leases: list[dict[str, object]] = []
    for lease in leases:
        status = str(lease.status or "unknown")
        by_state[status] = by_state.get(status, 0) + 1
        heartbeat_at = _aware(lease.heartbeat_at) if hasattr(lease, "heartbeat_at") else None
        if status in {"active", "claimed", "running"} and heartbeat_at is not None:
            age = (now - heartbeat_at).total_seconds()
            if age > _STALE_LEASE_SECONDS:
                stale_leases.append(
                    {
                        "lease_id": lease.id,
                        "run_id": lease.run_id,
                        "phase_name": lease.phase_name,
                        "worker_id": lease.worker_id,
                        "heartbeat_age_seconds": round(age, 1),
                    }
                )

    workers = (
        db.query(WorkerRuntimeStatus)
        .order_by(WorkerRuntimeStatus.heartbeat_at.desc())
        .all()
    )
    worker_rows: list[dict[str, object]] = []
    stale_workers: list[dict[str, object]] = []
    for worker in workers:
        heartbeat_at = _aware(worker.heartbeat_at)
        age = (now - heartbeat_at).total_seconds() if heartbeat_at else None
        row = {
            "worker_id": worker.worker_id,
            "hostname": worker.hostname,
            "status": worker.status,
            "current_run_id": worker.current_run_id,
            "current_phase": worker.current_phase,
            "heartbeat_at": heartbeat_at.isoformat() if heartbeat_at else "",
            "heartbeat_age_seconds": round(age, 1) if age is not None else None,
        }
        worker_rows.append(row)
        if age is not None and age > _STALE_HEARTBEAT_SECONDS and worker.status in {"claimed", "running"}:
            stale_workers.append(row)

    latest_age = next(
        (row["heartbeat_age_seconds"] for row in worker_rows if row["heartbeat_age_seconds"] is not None),
        None,
    )
    return {
        "generated_at": now.isoformat(),
        "leases": {
            "total": len(leases),
            "by_state": by_state,
            "stale": stale_leases,
        },
        "workers": {
            "total": len(worker_rows),
            "rows": worker_rows,
            "stale": stale_workers,
            "latest_heartbeat_age_seconds": latest_age,
        },
        "thresholds": {
            "stale_heartbeat_seconds": _STALE_HEARTBEAT_SECONDS,
            "stale_lease_seconds": _STALE_LEASE_SECONDS,
        },
    }
