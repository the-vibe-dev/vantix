"""V25-06 — structured diff between original and replayed turns.

Given two BusEvent rows for the same logical turn (one on the base
branch, one on a branch produced by ``branch_exec.re_execute``), produce
a ``TurnDiff`` describing what changed: action set, observation outcome,
or evaluator critique. The diff is stable JSON so it can be fed to UI,
attached to ReplayDiff rows, or signed alongside a ReplaySpec.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from secops.models import BusEvent


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _payload_sha(payload: dict[str, Any] | None) -> str:
    return hashlib.sha256(_canonical(payload or {})).hexdigest()


@dataclass
class TurnDiff:
    turn_id: int
    seq: int
    agent: str
    type: str
    kind: str
    lhs_payload_sha: str
    rhs_payload_sha: str
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def differs(self) -> bool:
        return self.kind != "identical"


def _action_set(payload: dict[str, Any]) -> list[dict[str, Any]]:
    actions = payload.get("actions") if isinstance(payload, dict) else None
    if not isinstance(actions, list):
        return []
    out: list[dict[str, Any]] = []
    for a in actions:
        if not isinstance(a, dict):
            continue
        out.append({
            "action_type": a.get("action_type", ""),
            "objective": a.get("objective", ""),
            "target_ref": a.get("target_ref", ""),
        })
    return out


def diff_turn(lhs: BusEvent | None, rhs: BusEvent | None) -> TurnDiff:
    """Compare two events at the same (turn_id, seq) across branches."""
    if lhs is None and rhs is None:
        return TurnDiff(turn_id=-1, seq=-1, agent="", type="", kind="missing_both",
                        lhs_payload_sha="", rhs_payload_sha="", summary="both sides absent")
    if lhs is None:
        return TurnDiff(
            turn_id=int(rhs.turn_id), seq=int(rhs.seq), agent=str(rhs.agent), type=str(rhs.type),
            kind="lhs_missing", lhs_payload_sha="",
            rhs_payload_sha=_payload_sha(rhs.payload_json),
            summary=f"event present only on rhs (seq={rhs.seq})",
        )
    if rhs is None:
        return TurnDiff(
            turn_id=int(lhs.turn_id), seq=int(lhs.seq), agent=str(lhs.agent), type=str(lhs.type),
            kind="rhs_missing", lhs_payload_sha=_payload_sha(lhs.payload_json),
            rhs_payload_sha="",
            summary=f"event present only on lhs (seq={lhs.seq})",
        )

    lhs_payload = dict(lhs.payload_json or {})
    rhs_payload = dict(rhs.payload_json or {})
    lhs_sha = _payload_sha(lhs_payload)
    rhs_sha = _payload_sha(rhs_payload)
    if lhs_sha == rhs_sha and str(lhs.agent) == str(rhs.agent) and str(lhs.type) == str(rhs.type):
        return TurnDiff(
            turn_id=int(lhs.turn_id), seq=int(lhs.seq), agent=str(lhs.agent), type=str(lhs.type),
            kind="identical", lhs_payload_sha=lhs_sha, rhs_payload_sha=rhs_sha,
            summary="payloads match",
        )

    detail: dict[str, Any] = {}
    if lhs.type != rhs.type:
        kind = "type_changed"
        detail = {"lhs_type": lhs.type, "rhs_type": rhs.type}
        summary = f"type {lhs.type} -> {rhs.type}"
    elif str(lhs.type) in ("plan_proposed", "plan_revised", "plan", "plan_blocked"):
        lhs_actions = _action_set(lhs_payload)
        rhs_actions = _action_set(rhs_payload)
        added = [a for a in rhs_actions if a not in lhs_actions]
        removed = [a for a in lhs_actions if a not in rhs_actions]
        kind = "plan_actions_changed"
        detail = {"added": added, "removed": removed}
        summary = f"plan delta: +{len(added)} -{len(removed)} actions"
    elif str(lhs.type) in ("observation_recorded", "observation"):
        kind = "observation_changed"
        detail = {
            "lhs_status": lhs_payload.get("status"),
            "rhs_status": rhs_payload.get("status"),
            "lhs_summary": lhs_payload.get("summary"),
            "rhs_summary": rhs_payload.get("summary"),
        }
        summary = f"observation status {lhs_payload.get('status')} -> {rhs_payload.get('status')}"
    elif str(lhs.type) in ("turn_committed", "critique"):
        kind = "critique_changed"
        detail = {"lhs": lhs_payload, "rhs": rhs_payload}
        summary = "evaluator critique payload changed"
    else:
        kind = "payload_changed"
        detail = {"lhs": lhs_payload, "rhs": rhs_payload}
        summary = f"payload sha {lhs_sha[:8]} -> {rhs_sha[:8]}"

    return TurnDiff(
        turn_id=int(lhs.turn_id), seq=int(lhs.seq), agent=str(lhs.agent), type=str(lhs.type),
        kind=kind, lhs_payload_sha=lhs_sha, rhs_payload_sha=rhs_sha,
        summary=summary, detail=detail,
    )


def diff_branches(
    db: Session,
    *,
    run_id: str,
    base_branch: str,
    other_branch: str,
) -> list[TurnDiff]:
    """Pairwise-diff every event seq across two branches of the same run."""
    base = (
        db.query(BusEvent)
        .filter(BusEvent.run_id == run_id, BusEvent.branch_id == base_branch)
        .order_by(BusEvent.seq.asc())
        .all()
    )
    other = (
        db.query(BusEvent)
        .filter(BusEvent.run_id == run_id, BusEvent.branch_id == other_branch)
        .order_by(BusEvent.seq.asc())
        .all()
    )
    by_seq_lhs = {int(e.seq): e for e in base}
    by_seq_rhs = {int(e.seq): e for e in other}
    seqs = sorted(set(by_seq_lhs) | set(by_seq_rhs))
    return [diff_turn(by_seq_lhs.get(s), by_seq_rhs.get(s)) for s in seqs]


__all__ = ["TurnDiff", "diff_turn", "diff_branches"]
