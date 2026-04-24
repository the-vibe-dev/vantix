"""V2-14 — Typed query API over the attack graph.

The planner agent should not run ad-hoc SQL on ``attack_graph_*`` tables;
it asks concrete questions ("what services haven't I probed yet?", "what
CVEs have I collected against this host?") and this module answers. Keeps
the planner prompt grounded in graph state rather than raw fact dumps.

All queries are scoped to a single ``run_id`` because the graph is
per-run today (V2 may promote to engagement scope; query signatures stay
stable either way).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from secops.models import AttackGraphEdge, AttackGraphNode


@dataclass(frozen=True)
class GraphNodeView:
    id: str
    node_type: str
    stable_key: str
    label: str
    confidence: float
    metadata: dict[str, Any]

    @classmethod
    def from_row(cls, row: AttackGraphNode) -> "GraphNodeView":
        return cls(
            id=row.id,
            node_type=row.node_type,
            stable_key=row.stable_key,
            label=row.label or "",
            confidence=float(row.confidence or 0.0),
            metadata=dict(row.metadata_json or {}),
        )


@dataclass(frozen=True)
class GraphEdgeView:
    id: str
    edge_type: str
    source_node_id: str
    target_node_id: str
    confidence: float
    metadata: dict[str, Any]

    @classmethod
    def from_row(cls, row: AttackGraphEdge) -> "GraphEdgeView":
        return cls(
            id=row.id,
            edge_type=row.edge_type,
            source_node_id=row.source_node_id,
            target_node_id=row.target_node_id,
            confidence=float(row.confidence or 0.0),
            metadata=dict(row.metadata_json or {}),
        )


def _nodes(db: Session, run_id: str, node_type: str | None = None) -> list[AttackGraphNode]:
    q = db.query(AttackGraphNode).filter(AttackGraphNode.run_id == run_id)
    if node_type is not None:
        q = q.filter(AttackGraphNode.node_type == node_type)
    return q.all()


def _edges(db: Session, run_id: str, edge_type: str | None = None) -> list[AttackGraphEdge]:
    q = db.query(AttackGraphEdge).filter(AttackGraphEdge.run_id == run_id)
    if edge_type is not None:
        q = q.filter(AttackGraphEdge.edge_type == edge_type)
    return q.all()


def services_for_run(db: Session, run_id: str) -> list[GraphNodeView]:
    return [GraphNodeView.from_row(n) for n in _nodes(db, run_id, "service")]


def endpoints_for_run(db: Session, run_id: str) -> list[GraphNodeView]:
    return [GraphNodeView.from_row(n) for n in _nodes(db, run_id, "endpoint")]


def cves_for_run(db: Session, run_id: str) -> list[GraphNodeView]:
    return [GraphNodeView.from_row(n) for n in _nodes(db, run_id, "cve")]


def open_hypotheses(db: Session, run_id: str) -> list[GraphNodeView]:
    """Hypothesis nodes not yet refuted or promoted."""
    hyps = _nodes(db, run_id, "hypothesis")
    refutations = {
        e.target_node_id for e in _edges(db, run_id, "refutes")
    }
    promoted = {
        e.source_node_id for e in _edges(db, run_id, "has_finding")
    }
    out: list[GraphNodeView] = []
    for h in hyps:
        if h.id in refutations or h.id in promoted:
            continue
        # metadata flag from _ingest_fact carries validation state
        if bool((h.metadata_json or {}).get("validated")):
            continue
        out.append(GraphNodeView.from_row(h))
    return out


def refuted_hypotheses(db: Session, run_id: str) -> list[GraphNodeView]:
    negs = _nodes(db, run_id, "negative_evidence")
    return [GraphNodeView.from_row(n) for n in negs]


def unexplored_services(db: Session, run_id: str) -> list[GraphNodeView]:
    """Services the run knows about but has not yet produced endpoints or CVEs for.

    Heuristic: a service is "explored" if it has at least one outgoing
    edge (other than the ``exposes``/``runs`` edge coming from the
    target, which is how it was discovered in the first place).
    """
    services = _nodes(db, run_id, "service")
    if not services:
        return []
    # Edges where the service is the source (explored), or target nodes
    # hanging off the service via endpoint/cve via the same fact source.
    explored_ids: set[str] = set()
    for edge in _edges(db, run_id):
        if edge.edge_type in {"exposes", "runs"}:
            # "exposes"/"runs" go *from* target node *to* service; don't
            # count those as exploration of the service itself.
            continue
        explored_ids.add(edge.source_node_id)
        explored_ids.add(edge.target_node_id)
    return [GraphNodeView.from_row(s) for s in services if s.id not in explored_ids]


def neighbors(
    db: Session,
    run_id: str,
    node_id: str,
    *,
    direction: str = "out",
) -> list[tuple[GraphEdgeView, GraphNodeView]]:
    """Return (edge, other_node) pairs for a given node.

    ``direction`` is ``"out"`` (node is source), ``"in"`` (node is target),
    or ``"both"``.
    """
    if direction not in {"out", "in", "both"}:
        raise ValueError(f"direction must be out|in|both, got {direction!r}")
    all_edges = _edges(db, run_id)
    matches: list[AttackGraphEdge] = []
    for e in all_edges:
        if direction in {"out", "both"} and e.source_node_id == node_id:
            matches.append(e)
        if direction in {"in", "both"} and e.target_node_id == node_id:
            matches.append(e)
    if not matches:
        return []
    other_ids = {e.target_node_id if e.source_node_id == node_id else e.source_node_id for e in matches}
    nodes_by_id = {n.id: n for n in db.query(AttackGraphNode).filter(AttackGraphNode.id.in_(other_ids)).all()}
    out: list[tuple[GraphEdgeView, GraphNodeView]] = []
    for e in matches:
        other = e.target_node_id if e.source_node_id == node_id else e.source_node_id
        n = nodes_by_id.get(other)
        if n is None:
            continue
        out.append((GraphEdgeView.from_row(e), GraphNodeView.from_row(n)))
    return out


__all__ = [
    "GraphNodeView",
    "GraphEdgeView",
    "services_for_run",
    "endpoints_for_run",
    "cves_for_run",
    "open_hypotheses",
    "refuted_hypotheses",
    "unexplored_services",
    "neighbors",
]
