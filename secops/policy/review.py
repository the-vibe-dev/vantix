"""Plan-review — a single policy check over a whole Plan before dispatch.

The action-time gate still runs per-action as defense in depth. This
review exists so the bus-level loop can reject an entire turn cheaply
when any step would be blocked, avoiding partial execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from secops.agents.contracts import ActionProposal
from secops.bus.messages import Plan
from secops.models import WorkspaceRun
from secops.services.policies import ExecutionPolicyService


ReviewVerdict = Literal["allow", "rewrite", "approval_required", "blocked"]


@dataclass(slots=True)
class PlanReview:
    verdict: ReviewVerdict
    blocked_count: int
    approval_count: int
    rewrite_count: int
    steps: list[dict[str, Any]] = field(default_factory=list)

    @property
    def should_execute(self) -> bool:
        return self.verdict in {"allow", "rewrite"}

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "blocked_count": self.blocked_count,
            "approval_count": self.approval_count,
            "rewrite_count": self.rewrite_count,
            "steps": list(self.steps),
        }


def _to_action_proposal(action) -> ActionProposal:
    return ActionProposal(
        action_type=action.action_type,
        objective=action.objective,
        target_ref=action.target_ref,
        risk=action.risk,
        agent_role=action.agent_role,
        inputs=dict(action.inputs),
        required_evidence=list(action.required_evidence),
        rationale=action.rationale,
    )


def review_plan(
    run: WorkspaceRun,
    plan: Plan,
    policies: ExecutionPolicyService,
) -> PlanReview:
    proposals = [_to_action_proposal(a) for a in plan.actions]
    result = policies.compile_action_plan(run, proposals)
    return PlanReview(
        verdict=result.verdict,  # type: ignore[arg-type]
        blocked_count=result.blocked_count,
        approval_count=result.approval_count,
        rewrite_count=result.rewrite_count,
        steps=[
            {
                "index": s.index,
                "action_type": s.action_type,
                "verdict": s.verdict,
                "reason": s.reason,
                "risk": s.risk,
                "target_ref": s.target_ref,
                "rewrite": s.rewrite,
                "approval_required": s.approval_required,
            }
            for s in result.steps
        ],
    )
