from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from secops.policy.capabilities import project_capabilities
from secops.services.policies import ExecutionPolicyService


def _run(**cfg):
    return SimpleNamespace(status="running", config_json=cfg)


def test_projection_partitions_verdicts():
    policies = ExecutionPolicyService()
    with patch("secops.services.policies.settings") as settings:
        settings.enable_script_execution = False
        settings.enable_codex_execution = True
        settings.enable_write_execution = False
        caps = project_capabilities(_run(), policies)
    assert "codex" in caps.allowed
    assert "script" in caps.blocked
    assert "write_action" in caps.approval_required
    assert caps.reasons["codex"]


def test_can_and_requires_approval():
    policies = ExecutionPolicyService()
    with patch("secops.services.policies.settings") as settings:
        settings.enable_script_execution = True
        settings.enable_codex_execution = True
        settings.enable_write_execution = True
        caps = project_capabilities(_run(), policies)
    assert caps.can("codex")
    assert caps.can("CODEX ")  # normalized
    # exploit_validation needs operator grant, so approval-required unless granted
    assert caps.requires_approval("exploit_validation")


def test_persistent_grants_surface_as_allowed():
    policies = ExecutionPolicyService()
    with patch("secops.services.policies.settings") as settings:
        settings.enable_script_execution = True
        settings.enable_codex_execution = True
        settings.enable_write_execution = True
        caps = project_capabilities(
            _run(approval_grants_persistent={"exploit_validation": True}), policies
        )
    assert caps.can("exploit_validation")


def test_planner_input_is_the_allowed_list():
    policies = ExecutionPolicyService()
    with patch("secops.services.policies.settings") as settings:
        settings.enable_script_execution = True
        settings.enable_codex_execution = True
        settings.enable_write_execution = True
        caps = project_capabilities(_run(), policies)
    assert caps.as_planner_input() == caps.allowed
