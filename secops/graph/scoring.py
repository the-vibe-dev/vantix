"""V2-16 — Deterministic edge scoring.

Score = severity × exploitability × reachability, with per-edge-type
priors. Deterministic (no RNG, no clock). The planner ranks its frontier
by this score so replay produces the same ordering.

Severity: pulled from CVE/finding metadata (cvss), defaults to medium.
Exploitability: pulled from CVE metadata (exploitability_ease), defaults
to 0.5, bumped for nodes with known public exploits.
Reachability: confidence on the discovery edge (how sure are we the
service is exposed / the fact came from a reliable source).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secops.graph.query import GraphEdgeView, GraphNodeView


# Baseline exploration value per edge type. Higher = the planner prefers
# to explore this kind of relationship first.
EDGE_TYPE_PRIORS: dict[str, float] = {
    "has_hypothesis": 0.9,
    "has_intel": 0.7,
    "has_finding": 0.6,
    "has_endpoint": 0.6,
    "exposes": 0.5,
    "runs": 0.5,
    "refutes": 0.05,  # already refuted — don't waste turns
}


def _severity_from_metadata(meta: dict[str, Any]) -> float:
    """Map severity/cvss hints to [0, 1]."""
    if "cvss" in meta:
        try:
            cvss = float(meta["cvss"])
            return max(0.0, min(1.0, cvss / 10.0))
        except (TypeError, ValueError):
            pass
    sev = str(meta.get("severity") or "").lower()
    return {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.25,
        "info": 0.1,
    }.get(sev, 0.5)


def _exploitability_from_metadata(meta: dict[str, Any]) -> float:
    for key in ("exploitability", "exploitability_ease"):
        if key in meta:
            try:
                v = float(meta[key])
                return max(0.0, min(1.0, v))
            except (TypeError, ValueError):
                pass
    if bool(meta.get("public_exploit")) or bool(meta.get("has_exploit")):
        return 0.9
    return 0.5


def _reachability(edge_conf: float, node_conf: float) -> float:
    # Reachability is bounded by the weakest link in the discovery chain.
    return max(0.0, min(1.0, min(edge_conf or 0.0, node_conf or 0.0) or 0.0))


@dataclass(frozen=True)
class ScoredEdge:
    edge: GraphEdgeView
    target: GraphNodeView
    severity: float
    exploitability: float
    reachability: float
    prior: float
    score: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge.id,
            "edge_type": self.edge.edge_type,
            "target_id": self.target.id,
            "target_label": self.target.label,
            "severity": round(self.severity, 4),
            "exploitability": round(self.exploitability, 4),
            "reachability": round(self.reachability, 4),
            "prior": round(self.prior, 4),
            "score": round(self.score, 6),
        }


def score_edge(edge: GraphEdgeView, target: GraphNodeView) -> ScoredEdge:
    meta = {**target.metadata, **edge.metadata}
    severity = _severity_from_metadata(meta)
    exploitability = _exploitability_from_metadata(meta)
    reach = _reachability(edge.confidence, target.confidence)
    prior = EDGE_TYPE_PRIORS.get(edge.edge_type, 0.4)
    score = prior * severity * exploitability * reach
    return ScoredEdge(
        edge=edge,
        target=target,
        severity=severity,
        exploitability=exploitability,
        reachability=reach,
        prior=prior,
        score=score,
    )


def rank_edges(pairs: list[tuple[GraphEdgeView, GraphNodeView]]) -> list[ScoredEdge]:
    """Score + sort descending. Stable on ties (edge.id as tiebreaker)."""
    scored = [score_edge(e, n) for e, n in pairs]
    scored.sort(key=lambda s: (-s.score, s.edge.id))
    return scored


__all__ = ["EDGE_TYPE_PRIORS", "ScoredEdge", "score_edge", "rank_edges"]
