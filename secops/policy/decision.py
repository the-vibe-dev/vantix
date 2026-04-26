"""V25-08 — extended policy verdicts.

The legacy PlanReview verdict is 4-valued (allow / rewrite /
approval_required / blocked). v2.5 adds verdicts that let a policy
respond to a Plan without bouncing back through the LLM:

  * ``rewrite_plan``       — replace the entire Plan with ``rewrite``.
  * ``downgrade_action``   — patch specific actions in place via ``downgrade``.
  * ``route_to_verifier``  — pin executor dispatch to ``verifier_id``.
  * ``sandbox_only``       — execute under ``sandbox`` constraints.

Per plan critical-decision #4 the loop must not bounce a rewritten plan
back through the planner LLM. ``Decision.apply`` produces the patched
Plan deterministically and the loop dispatches it directly.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from secops.bus.messages import Plan, ProposedAction
from secops.policy.review import PlanReview


Verdict = Literal[
    "allow",
    "block",
    "approval_required",
    "rewrite_plan",
    "downgrade_action",
    "route_to_verifier",
    "sandbox_only",
]


class SandboxConstraints(BaseModel):
    """Subset of execution constraints a policy can attach to a plan."""

    model_config = ConfigDict(extra="forbid")

    network: bool = False
    filesystem: list[str] = Field(default_factory=list)
    max_runtime_seconds: int | None = None
    allow_state_mutation: bool = False


class Decision(BaseModel):
    """Extended policy decision over a Plan.

    Carries enough context that the planner-loop can honor the verdict
    without consulting the LLM again. Only the field appropriate to the
    verdict is populated; the others stay None / empty.
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    verdict: Verdict
    reason: str = ""
    rewrite: Plan | None = None
    downgrade: dict[int, ProposedAction] = Field(default_factory=dict)
    verifier_id: str | None = None
    sandbox: SandboxConstraints | None = None
    review: PlanReview | None = None

    @property
    def should_execute(self) -> bool:
        return self.verdict in {
            "allow",
            "rewrite_plan",
            "downgrade_action",
            "route_to_verifier",
            "sandbox_only",
        }

    def apply(self, plan: Plan) -> Plan:
        """Return a Plan reflecting the verdict's mutation, if any."""
        if self.verdict == "rewrite_plan":
            if self.rewrite is None:
                raise ValueError("rewrite_plan verdict requires Decision.rewrite")
            patched = self.rewrite.model_copy(update={"turn_id": plan.turn_id})
            return patched
        if self.verdict == "downgrade_action":
            if not self.downgrade:
                raise ValueError("downgrade_action verdict requires Decision.downgrade")
            actions = list(plan.actions)
            for idx, replacement in self.downgrade.items():
                if 0 <= idx < len(actions):
                    actions[idx] = replacement
            return plan.model_copy(update={"actions": actions})
        return plan

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"verdict": self.verdict, "reason": self.reason}
        if self.rewrite is not None:
            out["rewrite"] = self.rewrite.model_dump()
        if self.downgrade:
            out["downgrade"] = {str(k): v.model_dump() for k, v in self.downgrade.items()}
        if self.verifier_id:
            out["verifier_id"] = self.verifier_id
        if self.sandbox is not None:
            out["sandbox"] = self.sandbox.model_dump()
        if self.review is not None:
            out["review"] = self.review.as_dict()
        return out


def from_review(review: PlanReview) -> Decision:
    """Adapt a legacy PlanReview into a Decision."""
    mapping: dict[str, Verdict] = {
        "allow": "allow",
        "rewrite": "allow",  # legacy step-level rewrite already baked into the plan
        "approval_required": "approval_required",
        "blocked": "block",
    }
    verdict: Verdict = mapping.get(review.verdict, "allow")
    return Decision(verdict=verdict, reason=f"plan_review={review.verdict}", review=review)


__all__ = ["Decision", "SandboxConstraints", "Verdict", "from_review"]
