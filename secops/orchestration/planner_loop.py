"""Bounded planner → executor → evaluator loop.

Runs one orchestration episode: the planner emits a Plan, the executor
dispatches each ProposedAction, the evaluator critiques the batch, and
the loop either replans (continuing) or terminates. Every message is
published to the AgentMessageBus with a run+branch+turn coordinate.

This is currently opt-in via ``settings.enable_agent_loop``; the legacy
``run_orchestrate_phase`` remains the default entrypoint until Phase 2
wires policy projection into the planner's state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from secops.agents.base import Agent, RunState
from secops.agents.evaluator import EvaluatorAgent
from secops.agents.executor import ExecutorAgent
from secops.agents.planner import PlannerAgent
from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope, Critique, Observation, Plan
from secops.policy.review import PlanReview


@dataclass
class LoopConfig:
    max_turns: int = 8
    max_actions_per_turn: int = 12
    stop_when_no_replan: bool = True


@dataclass
class LoopResult:
    turns_executed: int = 0
    plans: list[Plan] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    critiques: list[Critique] = field(default_factory=list)
    plan_reviews: list[PlanReview] = field(default_factory=list)
    terminated_reason: str = ""


StateBuilder = Callable[[str, int, Critique | None], RunState]
PlanReviewer = Callable[[Plan], PlanReview]


def run_planner_loop(
    *,
    bus: AgentMessageBus,
    run_id: str,
    branch_id: str = "main",
    planner: PlannerAgent,
    executor: ExecutorAgent,
    evaluator: EvaluatorAgent,
    build_state: StateBuilder,
    config: LoopConfig | None = None,
    review_plan: PlanReviewer | None = None,
) -> LoopResult:
    """Drive the planner/executor/evaluator loop and persist every message."""
    cfg = config or LoopConfig()
    result = LoopResult()
    last_critique: Critique | None = None

    for turn in range(cfg.max_turns):
        state = build_state(run_id, turn, last_critique)
        plan = planner.plan(state)
        bus.publish(
            BusEnvelope(
                run_id=run_id, branch_id=branch_id, turn_id=turn,
                agent="planner", type="plan", payload=plan.model_dump(),
            )
        )
        result.plans.append(plan)

        if not plan.actions:
            result.terminated_reason = "empty_plan"
            result.turns_executed = turn + 1
            break

        if review_plan is not None:
            review = review_plan(plan)
            result.plan_reviews.append(review)
            bus.publish(
                BusEnvelope(
                    run_id=run_id, branch_id=branch_id, turn_id=turn,
                    agent="planner", type="policy_decision",
                    payload={"phase": "plan_review", **review.as_dict()},
                )
            )
            if not review.should_execute:
                result.terminated_reason = f"plan_{review.verdict}"
                result.turns_executed = turn + 1
                break

        observations: list[Observation] = []
        for action in plan.actions[: cfg.max_actions_per_turn]:
            bus.publish(
                BusEnvelope(
                    run_id=run_id, branch_id=branch_id, turn_id=turn,
                    agent="executor", type="action", payload=action.model_dump(),
                )
            )
            obs = executor.execute(action)
            observations.append(obs)
            bus.publish(
                BusEnvelope(
                    run_id=run_id, branch_id=branch_id, turn_id=turn,
                    agent="executor", type="observation", payload=obs.model_dump(),
                )
            )
        result.observations.extend(observations)

        critique = evaluator.evaluate(observations)
        critique = critique.model_copy(update={"turn_id": turn})
        bus.publish(
            BusEnvelope(
                run_id=run_id, branch_id=branch_id, turn_id=turn,
                agent="evaluator", type="critique", payload=critique.model_dump(),
            )
        )
        result.critiques.append(critique)
        last_critique = critique

        result.turns_executed = turn + 1
        if cfg.stop_when_no_replan and not critique.should_replan:
            result.terminated_reason = "no_replan"
            break
    else:
        result.terminated_reason = "max_turns"

    return result


def _identity_agent_check(agent: Agent) -> None:
    # Runtime guard — surfaces misconfig before we enter the loop.
    _ = agent.role  # noqa: F841
