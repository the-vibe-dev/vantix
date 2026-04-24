"""Policy → capability projection.

The planner needs to know *before* it writes a plan what action kinds the
current policy will actually allow (or require approval for). Without
this, the LLM wastes turns proposing things the gate will reject.

``project_capabilities(run, policies)`` runs the policy's ``evaluate``
for every known action kind with ``consume_grants=False`` and returns a
``CapabilitySet`` describing the allowed and approval-gated surface. The
result is what the planner reads on ``RunState.capability_set``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secops.models import WorkspaceRun
from secops.services.policies import ExecutionPolicyService


KNOWN_ACTION_KINDS: tuple[str, ...] = (
    "script",
    "codex",
    "write_action",
    "filesystem_write",
    "recon_high_noise",
    "exploit_validation",
    "browser_assessment",
    "browser_auth",
    "browser_high_noise",
    "browser_sensitive_route",
    "external_network",
    "network",
)


@dataclass(slots=True)
class CapabilitySet:
    allowed: list[str] = field(default_factory=list)
    approval_required: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)

    def can(self, action_kind: str) -> bool:
        k = action_kind.strip().lower()
        return k in self.allowed

    def requires_approval(self, action_kind: str) -> bool:
        k = action_kind.strip().lower()
        return k in self.approval_required

    def as_planner_input(self) -> list[str]:
        """Returns the kinds safe to propose without operator approval."""
        return list(self.allowed)


def project_capabilities(
    run: WorkspaceRun,
    policies: ExecutionPolicyService,
    *,
    kinds: tuple[str, ...] = KNOWN_ACTION_KINDS,
) -> CapabilitySet:
    allowed: list[str] = []
    approval: list[str] = []
    blocked: list[str] = []
    reasons: dict[str, str] = {}
    for kind in kinds:
        decision = policies.evaluate(run, action_kind=kind, consume_grants=False)
        reasons[kind] = decision.reason
        verdict = decision.verdict
        if verdict == "block":
            blocked.append(kind)
        elif verdict == "require_approval":
            approval.append(kind)
        else:
            allowed.append(kind)
    return CapabilitySet(
        allowed=allowed,
        approval_required=approval,
        blocked=blocked,
        reasons=reasons,
    )
