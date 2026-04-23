from __future__ import annotations

from secops.agents.contracts import ActionProposal
from secops.models import WorkspaceRun
from secops.services.policies import ExecutionPolicyService


def _run(config: dict | None = None) -> WorkspaceRun:
    return WorkspaceRun(
        engagement_id="engagement-1",
        mode="pentest",
        workspace_id="policy-plan-test",
        status="running",
        target="10.10.10.10",
        config_json=config or {},
    )


def test_compile_action_plan_does_not_consume_approval_grants() -> None:
    run = _run({"approval_grants": {"exploit_validation": 1}})
    result = ExecutionPolicyService().compile_action_plan(
        run,
        [
            ActionProposal(
                action_type="exploit_validation",
                objective="validate candidate",
                risk="medium",
                target_ref="endpoint:/rest/user/login",
            )
        ],
    )

    assert result.verdict == "allow"
    assert result.steps[0].verdict == "allow_with_audit"
    assert run.config_json["approval_grants"]["exploit_validation"] == 1


def test_compile_action_plan_marks_approval_required() -> None:
    result = ExecutionPolicyService().compile_action_plan(
        _run(),
        [{"action_type": "browser_auth", "objective": "exercise login", "risk": "medium"}],
    )

    assert result.verdict == "approval_required"
    assert result.approval_count == 1
    assert result.steps[0].approval_required is True


def test_compile_action_plan_rewrites_high_risk_writes() -> None:
    result = ExecutionPolicyService().compile_action_plan(
        _run(),
        [
            {
                "action_type": "write_action",
                "objective": "mutate remote object",
                "risk": "high",
                "target_ref": "endpoint:/api/BasketItems/1",
            }
        ],
    )

    assert result.verdict in {"approval_required", "rewrite"}
    assert result.rewrite_count == 1
    assert result.steps[0].rewrite["prefer_action_type"] == "read_only_probe"
