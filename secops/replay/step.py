"""V25-05 — single-turn replay primitive.

Given a manifest turn entry and the live bus event for the same
``(run_id, branch_id, turn_id, seq)``, recompute the envelope sha256
and compare. The result is a ``ReplayStepResult`` consumed by the
replay engine and the branch-execute machinery (V25-06).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from secops.models import BusEvent
from secops.replay.turn_manifest import _envelope_sha256


@dataclass(frozen=True)
class ReplayStepResult:
    turn_id: int
    seq: int
    agent: str
    type: str
    expected_sha256: str
    actual_sha256: str
    divergence_kind: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def diverged(self) -> bool:
        return bool(self.divergence_kind)


def replay_turn(
    db: Session,
    *,
    run_id: str,
    branch_id: str,
    expected: dict[str, Any],
) -> ReplayStepResult:
    """Compare one manifest turn entry against the live bus event."""
    seq = int(expected.get("seq") or 0)
    turn_id = int(expected.get("turn_id") or 0)
    expected_sha = str(expected.get("msg_sha256") or "")

    row = (
        db.query(BusEvent)
        .filter(BusEvent.run_id == run_id, BusEvent.branch_id == branch_id, BusEvent.seq == seq)
        .first()
    )
    if row is None:
        return ReplayStepResult(
            turn_id=turn_id,
            seq=seq,
            agent=str(expected.get("agent") or ""),
            type=str(expected.get("type") or ""),
            expected_sha256=expected_sha,
            actual_sha256="",
            divergence_kind="missing_event",
            detail={"reason": f"no bus_event at seq={seq}"},
        )

    actual_sha = _envelope_sha256(row)
    divergence_kind = ""
    detail: dict[str, Any] = {}
    if actual_sha != expected_sha:
        divergence_kind = "envelope_sha_mismatch"
        detail = {
            "expected_agent": expected.get("agent"),
            "actual_agent": row.agent,
            "expected_type": expected.get("type"),
            "actual_type": row.type,
        }
    elif str(row.agent) != str(expected.get("agent") or ""):
        divergence_kind = "agent_mismatch"
    elif str(row.type) != str(expected.get("type") or ""):
        divergence_kind = "type_mismatch"

    return ReplayStepResult(
        turn_id=turn_id,
        seq=seq,
        agent=str(row.agent),
        type=str(row.type),
        expected_sha256=expected_sha,
        actual_sha256=actual_sha,
        divergence_kind=divergence_kind,
        detail=detail,
    )


__all__ = ["ReplayStepResult", "replay_turn"]
