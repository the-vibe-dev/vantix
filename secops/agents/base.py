"""Agent protocol — the surface every planner/executor/evaluator implements.

Phase 1 deliberately keeps this minimal: each role implements the one
method it cares about, the others default to no-ops. Later phases
specialize (policy-projection input for the planner, tool-registry input
for the executor, attack-graph input for the evaluator).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from secops.bus.messages import Critique, Observation, Plan, ProposedAction


@dataclass
class RunState:
    """Minimal snapshot the planner reads to produce a Plan."""

    run_id: str
    turn_id: int = 0
    branch_id: str = "main"
    facts: list[dict[str, Any]] = field(default_factory=list)
    open_hypotheses: list[str] = field(default_factory=list)
    recent_critique: Critique | None = None
    capability_set: list[str] = field(default_factory=list)
    budget_tokens: int | None = None
    frontier: list[dict[str, Any]] = field(default_factory=list)


@runtime_checkable
class Agent(Protocol):
    role: str

    def plan(self, state: RunState) -> Plan: ...
    def execute(self, action: ProposedAction) -> Observation: ...
    def evaluate(self, observations: list[Observation]) -> Critique: ...


class BaseAgent:
    """Convenience base with no-op defaults; subclasses override what they do."""

    role: str = "base"

    def plan(self, state: RunState) -> Plan:  # pragma: no cover - default
        return Plan(turn_id=state.turn_id, rationale="", actions=[])

    def execute(self, action: ProposedAction) -> Observation:  # pragma: no cover - default
        return Observation(
            action_id="",
            action_type=action.action_type,
            status="skipped",
            summary="no executor wired",
        )

    def evaluate(self, observations: list[Observation]) -> Critique:  # pragma: no cover - default
        return Critique(turn_id=0, observations=[o.action_id for o in observations])
