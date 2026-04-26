"""V25-06 — branch + re-execute primitive.

``branch_from_step`` (secops.replay.branch) copies bus events into a new
branch up to a fork point. ``branch_exec.re_execute`` extends that:
after the copy, replay the post-fork turns through agent callables so
the new branch contains a *re-derived* tail rather than just a verbatim
copy. Callers can optionally inject ``overrides`` keyed by turn_id to
mutate plan/action payloads at fork time.

The agent runners are caller-supplied (planner/executor/evaluator),
matching the v2 thin-agent interface. This module only orchestrates the
walk and persistence — it does not import the production agent stack so
tests can drive it with deterministic stubs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy.orm import Session

from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope
from secops.models import BusEvent, WorkspaceRun
from secops.replay.branch import branch_from_step
from secops.replay.diff import TurnDiff, diff_branches


TurnRunner = Callable[[BusEvent, dict[str, Any]], dict[str, Any] | None]
"""Given the original event and an override dict, return the new payload
to publish on the fork branch — or None to copy the original payload."""


@dataclass
class BranchExecResult:
    run_id: str
    base_branch: str
    new_branch_id: str
    fork_turn_id: int
    copied_count: int
    re_executed_count: int
    diffs: list[TurnDiff] = field(default_factory=list)


def re_execute(
    db: Session,
    *,
    run_id: str,
    fork_turn_id: int,
    base_branch: str = "main",
    new_branch_id: str,
    runner: TurnRunner | None = None,
    overrides: dict[int, dict[str, Any]] | None = None,
) -> BranchExecResult:
    """Fork ``(run, base_branch)`` at ``fork_turn_id`` and re-execute the tail.

    Steps:
      1. ``branch_from_step`` copies events with ``turn_id <= fork_turn_id``.
      2. For every base event with ``turn_id > fork_turn_id``, invoke
         ``runner(event, overrides[turn_id])`` to compute the new payload
         and publish it on ``new_branch_id``.
      3. Diff base vs new branch with ``diff_branches`` and return.
    """
    if db.get(WorkspaceRun, run_id) is None:
        raise ValueError(f"run not found: {run_id}")

    branch_result = branch_from_step(
        db,
        run_id=run_id,
        fork_turn_id=fork_turn_id,
        base_branch=base_branch,
        new_branch_id=new_branch_id,
    )

    overrides = overrides or {}
    bus = AgentMessageBus(db)

    tail = (
        db.query(BusEvent)
        .filter(BusEvent.run_id == run_id, BusEvent.branch_id == base_branch)
        .filter(BusEvent.turn_id > fork_turn_id)
        .order_by(BusEvent.seq.asc())
        .all()
    )

    re_executed = 0
    for ev in tail:
        override = overrides.get(int(ev.turn_id), {})
        new_payload: dict[str, Any]
        if runner is not None:
            produced = runner(ev, override)
            new_payload = dict(produced) if produced is not None else dict(ev.payload_json or {})
        else:
            base_payload = dict(ev.payload_json or {})
            base_payload.update(override)
            new_payload = base_payload
        bus.publish(
            BusEnvelope(
                run_id=run_id,
                branch_id=new_branch_id,
                turn_id=int(ev.turn_id),
                agent=ev.agent,  # type: ignore[arg-type]
                type=ev.type,  # type: ignore[arg-type]
                payload=new_payload,
                parent_turn_id=int(fork_turn_id),
                caused_by_fact_ids=list(ev.caused_by_fact_ids or []),
            )
        )
        re_executed += 1

    diffs = diff_branches(db, run_id=run_id, base_branch=base_branch, other_branch=new_branch_id)
    return BranchExecResult(
        run_id=run_id,
        base_branch=base_branch,
        new_branch_id=new_branch_id,
        fork_turn_id=fork_turn_id,
        copied_count=branch_result.copied_count,
        re_executed_count=re_executed,
        diffs=diffs,
    )


__all__ = ["BranchExecResult", "TurnRunner", "re_execute"]
