"""PlannerAgent — emits a Plan given a RunState.

The production planner will be LLM-backed; this module provides the
wiring skeleton plus a ``StaticPlanner`` used by tests and deterministic
replay. LLM binding lands with the Phase 1 orchestrate-phase rewrite.
"""

from __future__ import annotations

from typing import Callable

from secops.agents.base import BaseAgent, RunState
from secops.bus.messages import Plan, ProposedAction


PlanFn = Callable[[RunState], Plan]


class PlannerAgent(BaseAgent):
    role = "planner"

    def __init__(self, plan_fn: PlanFn) -> None:
        self._plan_fn = plan_fn

    def plan(self, state: RunState) -> Plan:
        plan = self._plan_fn(state)
        if plan.turn_id != state.turn_id:
            plan = plan.model_copy(update={"turn_id": state.turn_id})
        return plan


class StaticPlanner(PlannerAgent):
    """Returns the same ordered actions on every turn. Deterministic; for tests."""

    def __init__(self, actions: list[ProposedAction], *, rationale: str = "") -> None:
        def _fn(state: RunState) -> Plan:
            return Plan(turn_id=state.turn_id, rationale=rationale, actions=list(actions))

        super().__init__(_fn)
