"""V2-19 — Web-app specialist reference agent.

A thin planner that, given a ``RunState`` carrying a graph frontier of
endpoints/services for an HTTP target, proposes a bounded set of
``ProposedAction``s (routes to crawl, injection probes to run). Built
entirely against the public SDK surface — the only ``secops.*`` import
is the re-export through ``vantix_sdk`` (see plan §9 success criterion).

This file is *reference*, not production: it exists to prove the SDK
shape is sufficient for third parties to ship a specialist without
cracking into internal modules.
"""

from __future__ import annotations

from typing import Any

import vantix_sdk as vx


WEB_ACTION_KIND = "web_probe"
MAX_ACTIONS_PER_TURN = 5


class WebAppAgent(vx.BaseAgent):
    """Propose lightweight HTTP recon actions from graph frontier."""

    role = "specialist:web_app"

    def __init__(self, *, action_kind: str = WEB_ACTION_KIND, risk: str = "medium"):
        self._action_kind = action_kind
        self._risk = risk

    def plan(self, state: vx.RunState) -> vx.Plan:
        frontier = list(state.frontier or [])
        actions: list[vx.ProposedAction] = []
        for item in frontier[:MAX_ACTIONS_PER_TURN]:
            if not self._is_web_candidate(item):
                continue
            label = str(item.get("label") or item.get("node_id") or "")
            actions.append(
                vx.ProposedAction(
                    action_type=self._action_kind,
                    objective=f"probe {label}",
                    risk=self._risk,  # type: ignore[arg-type]
                    inputs={"target": label, "source": item.get("kind", "")},
                )
            )
        return vx.Plan(
            turn_id=state.turn_id,
            rationale="web specialist: enumerate endpoints and probe for common issues",
            actions=actions,
        )

    @staticmethod
    def _is_web_candidate(item: dict[str, Any]) -> bool:
        kind = str(item.get("kind") or "")
        label = str(item.get("label") or "").lower()
        detail = item.get("detail") or {}
        detail_label = str((detail.get("target_label") if isinstance(detail, dict) else "") or "").lower()
        # Graph edges whose target is an endpoint, or hypotheses tagged web.
        if kind == "scored_edge" and ("endpoint" in label or "http" in label or "/" in detail_label):
            return True
        if kind == "unexplored_service" and any(tok in label for tok in ("http", ":80", ":443", ":8080")):
            return True
        if kind == "open_hypothesis":
            meta = (item.get("detail") or {}).get("metadata") or {}
            tags = [str(t).lower() for t in meta.get("tags", []) or []]
            return any(t in {"web", "http", "webapp"} for t in tags)
        return False


__all__ = ["WebAppAgent", "WEB_ACTION_KIND"]
