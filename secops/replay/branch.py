"""V2-13 — ``branch_from_step`` fork primitive.

Operator UX: "what if we hadn't run nmap here?" Forks a run at a given
``turn_id`` by copying the base branch's bus events up to and including
that turn into a new branch. The new branch inherits the base's seq up
to the fork point and continues from there; each copied event records
its source via ``parent_turn_id`` (unchanged if already set, otherwise
set to the fork turn).

Per plan decision #8 (branch-id tag on event rows), this is cheap: no
copy-on-write of facts, no fan-out. Divergence from the fork point
happens by publishing new events to ``new_branch_id``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope
from secops.models import BusEvent, WorkspaceRun


@dataclass(frozen=True)
class BranchResult:
    run_id: str
    base_branch: str
    new_branch_id: str
    fork_turn_id: int
    copied_count: int


def branch_from_step(
    db: Session,
    *,
    run_id: str,
    fork_turn_id: int,
    base_branch: str = "main",
    new_branch_id: str,
) -> BranchResult:
    """Copy events from ``(run_id, base_branch)`` where ``turn_id <= fork_turn_id``
    into ``(run_id, new_branch_id)``.

    Raises ``ValueError`` if the run does not exist, if the new branch
    already has events (to prevent clobbering an in-flight fork), or if
    there are no events at or before ``fork_turn_id`` on the base.
    """
    if db.get(WorkspaceRun, run_id) is None:
        raise ValueError(f"run not found: {run_id}")
    if base_branch == new_branch_id:
        raise ValueError("new_branch_id must differ from base_branch")

    existing = (
        db.query(BusEvent)
        .filter(BusEvent.run_id == run_id, BusEvent.branch_id == new_branch_id)
        .first()
    )
    if existing is not None:
        raise ValueError(f"branch {new_branch_id!r} already has events on run {run_id}")

    base_rows = (
        db.query(BusEvent)
        .filter(BusEvent.run_id == run_id)
        .filter(BusEvent.branch_id == base_branch)
        .filter(BusEvent.turn_id <= fork_turn_id)
        .order_by(BusEvent.seq.asc())
        .all()
    )
    if not base_rows:
        raise ValueError(
            f"no events on base branch {base_branch!r} at or before turn {fork_turn_id}"
        )

    bus = AgentMessageBus(db)
    copied = 0
    for row in base_rows:
        parent = row.parent_turn_id if row.parent_turn_id is not None else fork_turn_id
        bus.publish(
            BusEnvelope(
                run_id=run_id,
                branch_id=new_branch_id,
                turn_id=int(row.turn_id),
                agent=row.agent,  # type: ignore[arg-type]
                type=row.type,  # type: ignore[arg-type]
                payload=dict(row.payload_json or {}),
                parent_turn_id=parent,
                caused_by_fact_ids=list(row.caused_by_fact_ids or []),
                content_hash=row.content_hash or "",
                ts=row.created_at,
            )
        )
        copied += 1

    return BranchResult(
        run_id=run_id,
        base_branch=base_branch,
        new_branch_id=new_branch_id,
        fork_turn_id=fork_turn_id,
        copied_count=copied,
    )


__all__ = ["BranchResult", "branch_from_step"]
