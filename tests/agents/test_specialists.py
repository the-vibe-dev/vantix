"""V2-19 — reference specialist agents (web_app, ad)."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the SDK is importable exactly as a third-party consumer would.
_SDK_ROOT = Path(__file__).resolve().parents[2] / "sdk"
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

import vantix_sdk as vx

from secops.agents.specialists import AdAgent, WebAppAgent


def _state(**overrides):
    base = dict(run_id="r", turn_id=1, frontier=[])
    base.update(overrides)
    return vx.RunState(**base)


def test_web_specialist_filters_non_web_items():
    frontier = [
        {"kind": "scored_edge", "node_id": "e1", "label": "has_endpoint:/admin", "score": 0.9, "detail": {"target_label": "/admin"}},
        {"kind": "unexplored_service", "node_id": "s1", "label": "10.0.0.1:8080", "score": 0.5, "detail": {}},
        {"kind": "unexplored_service", "node_id": "s2", "label": "10.0.0.1:22", "score": 0.5, "detail": {}},
        {"kind": "open_hypothesis", "node_id": "h1", "label": "sqli guess", "score": 0.4, "detail": {"metadata": {"tags": ["web"]}}},
        {"kind": "open_hypothesis", "node_id": "h2", "label": "ad", "score": 0.4, "detail": {"metadata": {"tags": ["ad"]}}},
    ]
    plan = WebAppAgent().plan(_state(frontier=frontier))
    assert len(plan.actions) == 3
    labels = [a.objective for a in plan.actions]
    assert any("admin" in l for l in labels)
    assert any("8080" in l for l in labels)
    assert not any(":22" in l for l in labels)
    assert not any("ad" == l.split()[-1] for l in labels)


def test_web_specialist_respects_max_actions_per_turn():
    frontier = [
        {"kind": "scored_edge", "node_id": f"e{i}", "label": "has_endpoint:/p", "score": 1.0, "detail": {"target_label": "/p"}}
        for i in range(20)
    ]
    plan = WebAppAgent().plan(_state(frontier=frontier))
    assert len(plan.actions) == 5


def test_ad_specialist_matches_service_ports_and_tags():
    frontier = [
        {"kind": "unexplored_service", "node_id": "s1", "label": "10.0.0.1:445", "score": 0.5, "detail": {}},
        {"kind": "unexplored_service", "node_id": "s2", "label": "10.0.0.1:80", "score": 0.5, "detail": {}},
        {"kind": "scored_edge", "node_id": "e1", "label": "runs:kerberos", "score": 0.5, "detail": {}},
        {"kind": "open_hypothesis", "node_id": "h1", "label": "kerberoast", "score": 0.3, "detail": {"metadata": {"tags": ["kerberos"]}}},
    ]
    plan = AdAgent().plan(_state(frontier=frontier))
    objectives = [a.objective for a in plan.actions]
    assert any(":445" in o for o in objectives)
    assert any("kerberos" in o for o in objectives)
    assert not any(":80" in o for o in objectives)


def test_specialists_are_sdk_agents():
    assert isinstance(WebAppAgent(), vx.Agent)
    assert isinstance(AdAgent(), vx.Agent)


def test_empty_frontier_produces_empty_plan():
    assert WebAppAgent().plan(_state()).actions == []
    assert AdAgent().plan(_state()).actions == []
