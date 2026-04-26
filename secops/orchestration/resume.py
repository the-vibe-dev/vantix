"""V25-12 — pause / resume / auto-resume.

WorkspaceRun.status accepts ``paused | resuming | replaying | branched``
in addition to the legacy lifecycle states. ``pause(run_id)`` flips a
run to ``paused`` and emits a ``run_paused`` policy_decision event;
``resume(run_id)`` flips it back to ``resuming`` and exposes the latest
checkpoint (turn / branch / state-blob sha) so the caller can rebuild
in-memory state and continue the planner loop.

Auto-resume on app startup:
    Any run found in ``running`` status that has at least one checkpoint
    is reset to ``resuming`` so the worker_runtime picks it up. Runs
    without a checkpoint stay in ``running`` (they had no useful work).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope
from secops.models import RunTurnCheckpoint, WorkspaceRun
from secops.replay.cache import store as blob_store


VALID_RESUME_STATES = {"running", "paused", "resuming", "replaying", "branched"}


@dataclass(frozen=True)
class CheckpointSnapshot:
    run_id: str
    branch_id: str
    turn_id: int
    seq: int
    run_state_blob_sha: str


def write_checkpoint(
    db: Session,
    *,
    run_id: str,
    branch_id: str,
    turn_id: int,
    seq: int,
    state: dict[str, Any],
) -> CheckpointSnapshot:
    """Serialize ``state`` to a ContentBlob and persist a RunTurnCheckpoint row."""
    body = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sha = blob_store(db, body, content_type="application/json")
    row = RunTurnCheckpoint(
        run_id=run_id,
        branch_id=branch_id,
        turn_id=turn_id,
        seq=seq,
        run_state_blob_sha=sha,
    )
    db.add(row)
    db.flush()
    return CheckpointSnapshot(run_id=run_id, branch_id=branch_id, turn_id=turn_id, seq=seq, run_state_blob_sha=sha)


def latest_checkpoint(db: Session, run_id: str, *, branch_id: str = "main") -> CheckpointSnapshot | None:
    row = (
        db.query(RunTurnCheckpoint)
        .filter(RunTurnCheckpoint.run_id == run_id, RunTurnCheckpoint.branch_id == branch_id)
        .order_by(RunTurnCheckpoint.turn_id.desc(), RunTurnCheckpoint.seq.desc())
        .first()
    )
    if row is None:
        return None
    return CheckpointSnapshot(
        run_id=row.run_id,
        branch_id=row.branch_id,
        turn_id=int(row.turn_id),
        seq=int(row.seq),
        run_state_blob_sha=row.run_state_blob_sha,
    )


def pause(db: Session, run_id: str, *, reason: str = "operator-pause") -> WorkspaceRun:
    """Flip ``run.status`` to ``paused`` and emit a run_paused event."""
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise ValueError(f"run not found: {run_id}")
    run.status = "paused"
    bus = AgentMessageBus(db)
    bus.publish(
        BusEnvelope(
            run_id=run_id, branch_id="main", turn_id=0,
            agent="planner", type="run_paused",
            payload={"phase": "lifecycle", "verdict": "run_paused", "reason": reason},
        )
    )
    db.flush()
    return run


def resume(db: Session, run_id: str) -> CheckpointSnapshot | None:
    """Flip ``run.status`` to ``resuming`` and return the latest checkpoint."""
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise ValueError(f"run not found: {run_id}")
    if run.status not in VALID_RESUME_STATES:
        raise ValueError(f"cannot resume run in status {run.status!r}")
    run.status = "resuming"
    snap = latest_checkpoint(db, run_id)
    bus = AgentMessageBus(db)
    bus.publish(
        BusEnvelope(
            run_id=run_id, branch_id="main", turn_id=int(snap.turn_id) if snap else 0,
            agent="planner", type="run_resumed",
            payload={
                "phase": "lifecycle",
                "verdict": "run_resumed",
                "from_turn": snap.turn_id if snap else None,
                "from_seq": snap.seq if snap else None,
            },
        )
    )
    db.flush()
    return snap


def auto_resume_running_runs(db: Session) -> list[str]:
    """Reset any ``running`` rows that have a checkpoint to ``resuming``.

    Called from the app lifespan. Returns the list of run ids reset.
    """
    candidates = db.query(WorkspaceRun).filter(WorkspaceRun.status == "running").all()
    reset: list[str] = []
    for run in candidates:
        snap = latest_checkpoint(db, run.id)
        if snap is None:
            continue
        run.status = "resuming"
        reset.append(run.id)
    if reset:
        db.flush()
    return reset


__all__ = [
    "CheckpointSnapshot",
    "VALID_RESUME_STATES",
    "auto_resume_running_runs",
    "latest_checkpoint",
    "pause",
    "resume",
    "write_checkpoint",
]
