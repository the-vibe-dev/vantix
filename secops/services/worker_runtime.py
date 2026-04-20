from __future__ import annotations

import logging
import os
import socket
import threading
import time

_logger = logging.getLogger("secops.worker_runtime")
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from secops.db import SessionLocal
from secops.models import WorkerRuntimeStatus
from secops.services.workflows.engine import WorkflowEngine, WorkflowClaim
from secops.services.workflows.retries import classify_retry


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
        self._hostname = socket.gethostname()
        self._pid = os.getpid()
        self._worker_id = os.getenv("VANTIX_WORKER_ID", f"worker-{self._hostname}-{self._pid}")
        self._heartbeat_at = utcnow()
        self._claimed_run_id = ""
        self._claimed_phase = ""
        self._lease_expires_at = utcnow()
        self._last_error = ""

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
        self._upsert_worker_status(
            status="idle",
            current_run_id="",
            current_phase="",
            lease_expires_at=None,
            last_error="",
        )
        while not self._stop_event.is_set():
            try:
                with SessionLocal() as db:
                    claim = self._engine.claim_next_phase(db, worker_id=self._worker_id, lease_seconds=90)
                    db.commit()
                if claim is None:
                    self._claimed_run_id = ""
                    self._claimed_phase = ""
                    self._lease_expires_at = utcnow() + timedelta(seconds=5)
                    self._heartbeat_at = utcnow()
                    self._upsert_worker_status(
                        status="idle",
                        current_run_id="",
                        current_phase="",
                        lease_expires_at=None,
                        last_error="",
                    )
                    time.sleep(0.4)
                    continue

                self._claimed_run_id = claim.run_id
                self._claimed_phase = claim.phase_name
                self._lease_expires_at = claim.lease_expires_at
                self._heartbeat_at = utcnow()
                self._upsert_worker_status(
                    status="claimed",
                    current_run_id=claim.run_id,
                    current_phase=claim.phase_name,
                    lease_expires_at=claim.lease_expires_at,
                    last_error="",
                )
                heartbeat_stop = threading.Event()
                heartbeat_thread = threading.Thread(
                    target=self._heartbeat_loop,
                    args=(claim, heartbeat_stop),
                    daemon=True,
                    name=f"secops-worker-heartbeat-{self._worker_id}",
                )
                heartbeat_thread.start()
                try:
                    output = execution_manager.execute_phase(claim.run_id, claim.phase_name)
                    with SessionLocal() as db:
                        self._engine.mark_phase_completed(db, claim, output=output if isinstance(output, dict) else {})
                        db.commit()
                except Exception as exc:  # noqa: BLE001
                    self._last_error = str(exc)
                    with SessionLocal() as db:
                        error_class = exc.__class__.__name__
                        if "Blocked" in error_class:
                            self._engine.mark_phase_blocked(db, claim, reason=str(exc))
                        else:
                            decision = classify_retry(error_class)
                            if decision.retryable:
                                self._engine.schedule_retry(
                                    db,
                                    claim,
                                    retry_class=decision.retry_class.value,
                                    delay_seconds=decision.delay_seconds,
                                    reason=decision.reason or str(exc),
                                )
                            else:
                                self._engine.mark_phase_failed(
                                    db,
                                    claim,
                                    error_class=decision.retry_class.value or error_class,
                                    error_message=decision.reason or str(exc),
                                )
                        db.commit()
                finally:
                    heartbeat_stop.set()
                    heartbeat_thread.join(timeout=2)
            except Exception as exc:  # noqa: BLE001
                self._last_error = f"worker loop error: {exc.__class__.__name__}: {exc}"
                _logger.exception("worker loop error worker_id=%s", self._worker_id)
                self._upsert_worker_status(
                    status="error",
                    current_run_id=self._claimed_run_id,
                    current_phase=self._claimed_phase,
                    lease_expires_at=self._lease_expires_at,
                    last_error=self._last_error,
                )
                time.sleep(0.25)
            finally:
                self._heartbeat_at = utcnow()
                self._claimed_run_id = ""
                self._claimed_phase = ""
                self._lease_expires_at = utcnow() + timedelta(seconds=2)
                self._upsert_worker_status(
                    status="idle",
                    current_run_id="",
                    current_phase="",
                    lease_expires_at=None,
                    last_error="",
                )

    def _heartbeat_loop(self, claim: WorkflowClaim, stop_event: threading.Event) -> None:
        while not stop_event.wait(20):
            try:
                with SessionLocal() as db:
                    renewed = self._engine.renew_lease(db, claim, lease_seconds=90)
                    if renewed:
                        db.commit()
                        self._lease_expires_at = claim.lease_expires_at
                        self._heartbeat_at = utcnow()
                        self._upsert_worker_status(
                            status="running",
                            current_run_id=claim.run_id,
                            current_phase=claim.phase_name,
                            lease_expires_at=claim.lease_expires_at,
                            last_error="",
                        )
                    else:
                        db.rollback()
                        self._upsert_worker_status(
                            status="stale",
                            current_run_id=claim.run_id,
                            current_phase=claim.phase_name,
                            lease_expires_at=claim.lease_expires_at,
                            last_error="lease renewal failed",
                        )
                        break
            except Exception:  # noqa: BLE001
                self._upsert_worker_status(
                    status="error",
                    current_run_id=claim.run_id,
                    current_phase=claim.phase_name,
                    lease_expires_at=claim.lease_expires_at,
                    last_error="lease heartbeat exception",
                )
                break

    def _upsert_worker_status(
        self,
        *,
        status: str,
        current_run_id: str,
        current_phase: str,
        lease_expires_at: datetime | None,
        last_error: str,
    ) -> None:
        now = utcnow()
        self._heartbeat_at = now
        try:
            with SessionLocal() as db:
                row = db.query(WorkerRuntimeStatus).filter(WorkerRuntimeStatus.worker_id == self._worker_id).first()
                if row is None:
                    row = WorkerRuntimeStatus(
                        worker_id=self._worker_id,
                        hostname=self._hostname,
                        pid=self._pid,
                        started_at=now,
                    )
                    db.add(row)
                row.hostname = self._hostname
                row.pid = self._pid
                row.status = status
                row.current_run_id = current_run_id or ""
                row.current_phase = current_phase or ""
                row.lease_expires_at = lease_expires_at
                row.heartbeat_at = now
                row.last_error = (last_error or "")[:2000]
                row.metadata_json = {"thread_alive": bool(self._thread and self._thread.is_alive())}
                db.commit()
        except Exception:
            _logger.exception("worker status upsert failed worker_id=%s", self._worker_id)
            return


worker_runtime = WorkerRuntime()
