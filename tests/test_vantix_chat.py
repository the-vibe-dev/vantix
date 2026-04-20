from __future__ import annotations

from secops.models import WorkspaceRun
from secops.services.vantix import _should_start_new_engagement, is_quick_scan_request


def _run(*, target: str, status: str = "running", objective: str = "test") -> WorkspaceRun:
    return WorkspaceRun(
        engagement_id="e1",
        mode="pentest",
        workspace_id="w1",
        status=status,
        objective=objective,
        repo_path=".",
        target=target,
        config_json={},
    )


def test_should_start_new_when_explicit_target_changes() -> None:
    current = _run(target="192.168.1.95", status="running")
    assert _should_start_new_engagement(
        "move to 192.168.1.99",
        current,
        explicit_target="192.168.1.99",
    )


def test_quick_scan_request_detection() -> None:
    assert is_quick_scan_request("Run a quick scan on 10.10.10.10")
    assert not is_quick_scan_request("Run a full engagement on 10.10.10.10")
