"""V2-15 — Graph-fed planner frontier.

Builds a ranked list of next-action candidates the planner prompt is
seeded with instead of a raw fact dump. The frontier is:

1. Unexplored services — we know they exist but have collected no
   endpoints, CVEs, or hypotheses for them.
2. Open hypotheses — facts promoted to hypothesis nodes that have not
   been validated or refuted.
3. High-value neighbors — for each hypothesis/service/CVE, the top
   outgoing edges by :func:`secops.graph.scoring.score_edge`.

The planner prompt should ingest this as "here is the frontier of the
attack graph — pick the next edge to explore" (plan §4.Phase 4).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from secops.graph.query import (
    GraphNodeView,
    cves_for_run,
    neighbors,
    open_hypotheses,
    services_for_run,
    unexplored_services,
)
from secops.graph.scoring import ScoredEdge, rank_edges


@dataclass(frozen=True)
class FrontierItem:
    kind: str  # "unexplored_service" | "open_hypothesis" | "scored_edge"
    node_id: str
    label: str
    score: float
    detail: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "node_id": self.node_id,
            "label": self.label,
            "score": round(self.score, 6),
            "detail": self.detail,
        }


def _service_frontier(nodes: list[GraphNodeView]) -> list[FrontierItem]:
    return [
        FrontierItem(
            kind="unexplored_service",
            node_id=n.id,
            label=n.label,
            # Unexplored services start at the edge-type prior for
            # "exposes" so they compete directly with scored edges.
            score=0.5 * max(n.confidence, 0.1),
            detail={"stable_key": n.stable_key, "metadata": n.metadata},
        )
        for n in nodes
    ]


def _hypothesis_frontier(nodes: list[GraphNodeView]) -> list[FrontierItem]:
    items: list[FrontierItem] = []
    for n in nodes:
        meta = n.metadata or {}
        sev = str(meta.get("severity") or "medium").lower()
        sev_weight = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.1}.get(sev, 0.5)
        items.append(
            FrontierItem(
                kind="open_hypothesis",
                node_id=n.id,
                label=n.label,
                score=sev_weight * max(n.confidence, 0.25),
                detail={"stable_key": n.stable_key, "metadata": meta},
            )
        )
    return items


def build_frontier(
    db: Session,
    run_id: str,
    *,
    limit: int = 20,
) -> list[FrontierItem]:
    """Return up to ``limit`` ranked frontier items for the planner."""
    items: list[FrontierItem] = []
    items.extend(_service_frontier(unexplored_services(db, run_id)))
    items.extend(_hypothesis_frontier(open_hypotheses(db, run_id)))

    # Expand neighbors of services, CVEs, and hypotheses; score each edge.
    seed_nodes: list[GraphNodeView] = []
    seed_nodes.extend(services_for_run(db, run_id))
    seed_nodes.extend(cves_for_run(db, run_id))
    seed_nodes.extend(open_hypotheses(db, run_id))
    seen: set[str] = set()
    scored_edges: list[ScoredEdge] = []
    for seed in seed_nodes:
        pairs = neighbors(db, run_id, seed.id, direction="out")
        for scored in rank_edges(pairs):
            if scored.edge.id in seen:
                continue
            seen.add(scored.edge.id)
            scored_edges.append(scored)
    for s in scored_edges:
        items.append(
            FrontierItem(
                kind="scored_edge",
                node_id=s.target.id,
                label=f"{s.edge.edge_type}:{s.target.label}",
                score=s.score,
                detail=s.as_dict(),
            )
        )

    items.sort(key=lambda it: (-it.score, it.node_id))
    return items[:limit]


__all__ = ["FrontierItem", "build_frontier"]
