from __future__ import annotations

from secops.services.policies import ExecutionPolicyService


class _Run:
    def __init__(self) -> None:
        self.status = "running"
        self.config_json = {"approval_grants": {"recon_high_noise": 1}}


def test_recon_high_noise_consumes_single_approval_grant() -> None:
    run = _Run()
    policy = ExecutionPolicyService()

    first = policy.evaluate(run, action_kind="recon_high_noise")
    second = policy.evaluate(run, action_kind="recon_high_noise")

    assert first.verdict == "allow_with_audit"
    assert second.verdict == "require_approval"
    assert run.config_json["approval_grants"]["recon_high_noise"] == 0
