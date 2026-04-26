"""V25-05 — replay execution engine.

Walks a ReplaySpec's turn manifest and asserts each entry's expected
``msg_sha256`` matches the live bus event. Records every comparison as a
``ReplayStep`` and every divergence as a ``ReplayDiff``. The final
``ReplayRun.status`` is ``passed`` (zero divergences) or ``diverged``.

The engine intentionally walks to completion on divergence (per plan
critical-decision #2): operators want a complete diff, not a fail-fast.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from secops.models import ReplayDiff, ReplayRun, ReplaySpec, ReplayStep
from secops.replay.spec import load as load_spec
from secops.replay.step import ReplayStepResult, replay_turn


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ReplayOutcome:
    replay_run_id: str
    spec_id: str
    status: str
    divergence_count: int
    steps: list[ReplayStepResult]


def replay(db: Session, spec_id: str) -> ReplayOutcome:
    """Execute a replay against the spec's manifest. Persists artifacts."""
    record = load_spec(db, spec_id)
    manifest = record.manifest
    turns: list[dict[str, Any]] = list(manifest.get("turns") or [])

    run_row = ReplayRun(spec_id=spec_id, status="running", divergence_count=0, summary_json={})
    db.add(run_row)
    db.flush()

    results: list[ReplayStepResult] = []
    divergences = 0
    for entry in turns:
        result = replay_turn(
            db,
            run_id=record.run_id,
            branch_id=record.branch_id,
            expected=entry,
        )
        results.append(result)
        if result.diverged:
            divergences += 1
        db.add(
            ReplayStep(
                replay_run_id=run_row.id,
                turn_id=result.turn_id,
                seq=result.seq,
                agent=result.agent,
                type=result.type,
                expected_msg_sha256=result.expected_sha256,
                actual_msg_sha256=result.actual_sha256,
                divergence_kind=result.divergence_kind,
            )
        )
        if result.diverged:
            db.add(
                ReplayDiff(
                    replay_run_id=run_row.id,
                    turn_id=result.turn_id,
                    kind=result.divergence_kind,
                    lhs_blob_sha=result.expected_sha256,
                    rhs_blob_sha=result.actual_sha256,
                    summary=f"turn {result.turn_id} agent={result.agent} type={result.type} {result.divergence_kind}",
                    detail_json=dict(result.detail),
                )
            )

    status = "passed" if divergences == 0 else "diverged"
    run_row.status = status
    run_row.divergence_count = divergences
    run_row.completed_at = _utcnow()
    run_row.summary_json = {
        "turns_total": len(turns),
        "turns_compared": len(results),
        "divergence_count": divergences,
        "manifest_sha256": record.manifest_sha256,
    }
    db.flush()

    return ReplayOutcome(
        replay_run_id=run_row.id,
        spec_id=spec_id,
        status=status,
        divergence_count=divergences,
        steps=results,
    )


__all__ = ["ReplayOutcome", "replay"]
