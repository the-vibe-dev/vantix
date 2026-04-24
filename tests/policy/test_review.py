from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from secops.bus.messages import Plan, ProposedAction
from secops.policy.review import review_plan
from secops.services.policies import ExecutionPolicyService


def _run(**cfg):
    return SimpleNamespace(status="running", config_json=cfg)


def test_all_default_actions_allow():
    plan = Plan(
        turn_id=0,
        actions=[
            ProposedAction(action_type="network", objective=""),
            ProposedAction(action_type="external_network", objective=""),
        ],
    )
    review = review_plan(_run(), plan, ExecutionPolicyService())
    assert review.verdict == "allow"
    assert review.blocked_count == 0
    assert review.should_execute


def test_script_disabled_blocks_plan():
    plan = Plan(
        turn_id=0,
        actions=[ProposedAction(action_type="script", objective="run probe")],
    )
    with patch("secops.services.policies.settings") as settings:
        settings.enable_script_execution = False
        settings.enable_codex_execution = True
        settings.enable_write_execution = True
        review = review_plan(_run(), plan, ExecutionPolicyService())
    assert review.verdict == "blocked"
    assert review.blocked_count == 1
    assert not review.should_execute


def test_approval_required_surfaces_in_review():
    plan = Plan(
        turn_id=0,
        actions=[ProposedAction(action_type="exploit_validation", objective="", risk="high")],
    )
    review = review_plan(_run(), plan, ExecutionPolicyService())
    assert review.verdict == "approval_required"
    assert review.approval_count == 1
    # rewrite is also applied for high-risk exploit_validation
    assert review.rewrite_count == 1
    assert review.steps[0]["rewrite"]["reason"]


def test_review_dict_round_trip():
    plan = Plan(
        turn_id=0,
        actions=[ProposedAction(action_type="network", objective="")],
    )
    review = review_plan(_run(), plan, ExecutionPolicyService())
    d = review.as_dict()
    assert d["verdict"] == "allow"
    assert d["steps"][0]["action_type"] == "network"
