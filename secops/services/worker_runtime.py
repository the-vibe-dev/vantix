from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from secops.db import SessionLocal
from secops.services.workflows.engine import WorkflowEngine, WorkflowClaim


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class WorkerSnapshot:
    worker_id: str
    running: bool
    heartbeat_at: str
    claimed_run_id: str
    claimed_phase: str
    lease_expires_at: str


class WorkerRuntime:
    def __init__(self) -> None:
        self._engine = WorkflowEngine()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._worker_id = "worker-local-1"
        self._heartbeat_at = utcnow()
        self._claimed_run_id = ""
        self._claimed_phase = ""
        self._lease_expires_at = utcnow()

    def ensure_running(self, execution_manager) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._loop,
                args=(execution_manager,),
                daemon=True,
                name="secops-worker-runtime",
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=2)

    def snapshot(self) -> WorkerSnapshot:
        return WorkerSnapshot(
            worker_id=self._worker_id,
            running=bool(self._thread and self._thread.is_alive() and not self._stop_event.is_set()),
            heartbeat_at=self._heartbeat_at.isoformat(),
            claimed_run_id=self._claimed_run_id,
            claimed_phase=self._claimed_phase,
            lease_expires_at=self._lease_expires_at.isoformat() if self._lease_expires_at else "",
        )

    def _loop(self, execution_manager) -> None:
        while not self._stop_event.is_set():
            claim: WorkflowClaim | None = None
            with SessionLocal() as db:
                claim = self._engine.claim_next_phase(db, worker_id=self._worker_id, lease_seconds=90)
                db.commit()

            if claim is None:
                self._claimed_run_id = ""
                self._claimed_phase = ""
                self._lease_expires_at = utcnow() + timedelta(seconds=5)
                self._heartbeat_at = utcnow()
                time.sleep(0.4)
                continue

            self._claimed_run_id = claim.run_id
            self._claimed_phase = claim.phase_name
            self._lease_expires_at = claim.lease_expires_at
            self._heartbeat_at = utcnow()

            try:
                output = execution_manager.execute_phase(claim.run_id, claim.phase_name)
                with SessionLocal() as db:
                    self._engine.mark_phase_completed(db, claim, output=output if isinstance(output, dict) else {})
                    db.commit()
            except Exception as exc:  # noqa: BLE001
                with SessionLocal() as db:
                    error_class = exc.__class__.__name__
                    if "Blocked" in error_class:
                        self._engine.mark_phase_blocked(db, claim, reason=str(exc))
                    else:
                        self._engine.mark_phase_failed(
                            db,
                            claim,
                            error_class=error_class,
                            error_message=str(exc),
                        )
                    db.commit()
            finally:
                self._heartbeat_at = utcnow()
                self._claimed_run_id = ""
                self._claimed_phase = ""
                self._lease_expires_at = utcnow() + timedelta(seconds=2)


worker_runtime = WorkerRuntime()
