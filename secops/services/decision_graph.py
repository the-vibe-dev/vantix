"""V2-20 — Decision-graph service.

Produces a DAG per run where nodes are bus-event turns and edges are
causality (``parent_turn_id``). The decision graph lets the operator
ask "why this action → which policy decision → which fact → which
evidence" as required by plan §8.

The graph is derived deterministically from ``bus_events`` so a replay
reproduces the same DAG. Optionally filter to events attributed to a
specific finding via ``caused_by_fact_ids`` intersecting the finding's
supporting facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from secops.models import BusEvent


@dataclass(frozen=True)
class DecisionNode:
    id: str
    turn_id: int
    agent: str
    type: str
    seq: int
    content_hash: str
    payload_summary: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "turn_id": self.turn_id,
            "agent": self.agent,
            "type": self.type,
            "seq": self.seq,
            "content_hash": self.content_hash,
            "payload_summary": self.payload_summary,
        }


@dataclass(frozen=True)
class DecisionEdge:
    from_id: str
    to_id: str
    kind: str  # "turn_predecessor" | "causal_fact"

    def as_dict(self) -> dict[str, Any]:
        return {"from_id": self.from_id, "to_id": self.to_id, "kind": self.kind}


@dataclass
class DecisionGraph:
    run_id: str
    branch_id: str
    nodes: list[DecisionNode] = field(default_factory=list)
    edges: list[DecisionEdge] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "branch_id": self.branch_id,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.as_dict() for n in self.nodes],
            "edges": [e.as_dict() for e in self.edges],
        }


def _payload_summary(payload: dict[str, Any], ev_type: str) -> str:
    if not isinstance(payload, dict):
        return ""
    from secops.bus.messages import canonicalize_type
    canon = canonicalize_type(ev_type)
    if canon in ("plan_proposed", "plan_revised"):
        actions = payload.get("actions") or payload.get("applied_plan", {}).get("actions") or []
        return f"plan({len(actions)} actions)"
    if canon == "plan_blocked":
        return f"plan_blocked({payload.get('verdict', payload.get('reason', '?'))})"
    if canon == "action_dispatched":
        return f"action({payload.get('action_type', '?')})"
    if canon == "observation_recorded":
        return f"observation({payload.get('status', '?')})"
    if canon == "turn_committed":
        return f"critique(replan={payload.get('should_replan')})"
    if canon in ("policy_evaluated", "proof_created", "fact_promoted"):
        return f"{canon}({payload.get('verdict', payload.get('phase', '?'))})"
    if canon in ("run_paused", "run_resumed", "run_branched"):
        return f"{canon}({payload.get('reason', payload.get('verdict', ''))})"
    return canon


def build_decision_graph(
    db: Session,
    run_id: str,
    *,
    branch_id: str = "main",
    fact_ids: list[str] | None = None,
) -> DecisionGraph:
    """Build a DAG over bus events for ``(run_id, branch_id)``.

    If ``fact_ids`` is provided, restrict the graph to events whose
    ``caused_by_fact_ids`` intersect that set (plus their ancestors so
    the DAG remains connected).
    """
    rows = (
        db.query(BusEvent)
        .filter(BusEvent.run_id == run_id, BusEvent.branch_id == branch_id)
        .order_by(BusEvent.seq.asc())
        .all()
    )
    if not rows:
        return DecisionGraph(run_id=run_id, branch_id=branch_id)

    rows_by_id = {r.id: r for r in rows}
    by_turn: dict[int, list[BusEvent]] = {}
    for r in rows:
        by_turn.setdefault(int(r.turn_id), []).append(r)

    selected_ids: set[str] = set()
    if fact_ids:
        fact_set = set(fact_ids)
        for r in rows:
            if set(r.caused_by_fact_ids or []) & fact_set:
                selected_ids.add(r.id)
        # Pull in ancestors via parent_turn_id so the subgraph remains
        # connected to the plan that produced the causal action.
        for r in list(rows):
            if r.id not in selected_ids:
                continue
            parent = r.parent_turn_id
            while parent is not None:
                parent_rows = by_turn.get(int(parent), [])
                if not parent_rows:
                    break
                for pr in parent_rows:
                    selected_ids.add(pr.id)
                parent = parent_rows[0].parent_turn_id
    else:
        selected_ids = {r.id for r in rows}

    nodes: list[DecisionNode] = []
    edges: list[DecisionEdge] = []
    prev_turn_last: dict[int, str] = {}  # turn_id -> last event id

    for r in rows:
        if r.id not in selected_ids:
            continue
        nodes.append(
            DecisionNode(
                id=r.id,
                turn_id=int(r.turn_id),
                agent=str(r.agent),
                type=str(r.type),
                seq=int(r.seq),
                content_hash=r.content_hash or "",
                payload_summary=_payload_summary(r.payload_json or {}, str(r.type)),
            )
        )
        # Intra-turn edges: connect sequentially within the same turn.
        prev = prev_turn_last.get(int(r.turn_id))
        if prev is not None:
            edges.append(DecisionEdge(from_id=prev, to_id=r.id, kind="turn_predecessor"))
        prev_turn_last[int(r.turn_id)] = r.id

    # Inter-turn causal edges: a plan in turn N is caused by the
    # critique in turn (parent_turn_id).
    for r in rows:
        if r.id not in selected_ids:
            continue
        if r.parent_turn_id is None:
            continue
        parent_turn_events = by_turn.get(int(r.parent_turn_id), [])
        if not parent_turn_events:
            continue
        parent_id = parent_turn_events[-1].id
        if parent_id in selected_ids:
            edges.append(DecisionEdge(from_id=parent_id, to_id=r.id, kind="causal_fact"))

    return DecisionGraph(run_id=run_id, branch_id=branch_id, nodes=nodes, edges=edges)


__all__ = ["DecisionEdge", "DecisionGraph", "DecisionNode", "build_decision_graph"]
