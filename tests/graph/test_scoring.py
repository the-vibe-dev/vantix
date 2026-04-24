"""V2-16 — deterministic edge scoring."""
from __future__ import annotations

from secops.graph.query import GraphEdgeView, GraphNodeView
from secops.graph.scoring import EDGE_TYPE_PRIORS, rank_edges, score_edge


def _node(id_, label="", confidence=1.0, **meta):
    return GraphNodeView(id=id_, node_type="service", stable_key=id_, label=label, confidence=confidence, metadata=meta)


def _edge(id_, src, dst, edge_type, confidence=1.0, **meta):
    return GraphEdgeView(id=id_, edge_type=edge_type, source_node_id=src, target_node_id=dst, confidence=confidence, metadata=meta)


def test_score_uses_severity_exploitability_reachability_and_prior():
    target = _node("n1", severity="high", public_exploit=True)
    edge = _edge("e1", "src", "n1", "has_intel", confidence=0.9)
    s = score_edge(edge, target)
    # prior 0.7 × sev 0.8 × exploit 0.9 × reach 0.9 ≈ 0.4536
    assert round(s.score, 4) == 0.4536
    assert s.prior == EDGE_TYPE_PRIORS["has_intel"]


def test_cvss_numeric_overrides_severity_string():
    target = _node("n", severity="low", cvss=9.8)
    edge = _edge("e", "s", "n", "has_intel")
    s = score_edge(edge, target)
    assert s.severity >= 0.9


def test_rank_edges_descending_deterministic():
    # Two edges with different scores
    n_hi = _node("hi", severity="critical", public_exploit=True)
    n_lo = _node("lo", severity="low")
    e_hi = _edge("e_hi", "src", "hi", "has_intel")
    e_lo = _edge("e_lo", "src", "lo", "has_intel")
    # Two edges with identical scores -> deterministic tiebreaker on edge.id
    n_a = _node("tie_a", severity="medium")
    n_b = _node("tie_b", severity="medium")
    e_a = _edge("zz_a", "src", "tie_a", "has_endpoint")
    e_b = _edge("zz_b", "src", "tie_b", "has_endpoint")

    ranked = rank_edges([(e_lo, n_lo), (e_hi, n_hi), (e_b, n_b), (e_a, n_a)])
    ids = [r.edge.id for r in ranked]
    # Top is e_hi, then tied pair in edge.id order, then e_lo
    assert ids[0] == "e_hi"
    assert ids[-1] == "e_lo"
    assert ids.index("zz_a") < ids.index("zz_b")


def test_reachability_floors_to_weakest_link():
    target = _node("n", severity="high", confidence=0.2)
    edge = _edge("e", "s", "n", "has_intel", confidence=0.9)
    s = score_edge(edge, target)
    assert s.reachability == 0.2


def test_refutes_edges_score_very_low():
    target = _node("n", severity="critical", public_exploit=True)
    edge = _edge("e", "s", "n", "refutes")
    s = score_edge(edge, target)
    # Even a critical-target refutes edge stays <= prior 0.05
    assert s.score <= EDGE_TYPE_PRIORS["refutes"]
