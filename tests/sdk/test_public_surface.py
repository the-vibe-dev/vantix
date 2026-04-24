"""V2-17 — SDK public surface smoke test.

Covers plan §9 success criterion: a third-party agent built against
``vantix_sdk`` should be able to construct messages, implement the Agent
protocol, and register a Tool without importing from ``secops.*``.
"""
from __future__ import annotations

import vantix_sdk as vx


def test_public_symbols_exist():
    for name in (
        "Agent", "BaseAgent", "RunState",
        "Tool", "ToolResult",
        "Plan", "ProposedAction", "Observation", "Evidence",
        "Critique", "PolicyDecision", "BusEnvelope",
        "PlanReview",
    ):
        assert hasattr(vx, name), f"missing public symbol: {name}"


def test_version_is_string():
    assert isinstance(vx.__version__, str)
    assert vx.__version__.count(".") == 2


def test_third_party_agent_can_be_constructed_without_secops_imports():
    # A hypothetical third-party planner lives in their own module and
    # only uses the SDK types.
    class MyPlanner(vx.BaseAgent):
        role = "my_planner"

        def plan(self, state: vx.RunState) -> vx.Plan:
            return vx.Plan(
                turn_id=state.turn_id,
                rationale="hello",
                actions=[vx.ProposedAction(action_type="network", objective="probe")],
            )

    planner = MyPlanner()
    assert isinstance(planner, vx.Agent)

    state = vx.RunState(run_id="run_1", turn_id=0)
    out = planner.plan(state)
    assert isinstance(out, vx.Plan)
    assert out.actions[0].action_type == "network"


def test_third_party_tool_conforms_to_protocol():
    class MyTool:
        name = "echo"

        def run(self, inputs):
            return vx.ToolResult(status="completed", summary=f"echoed {inputs!r}")

    tool = MyTool()
    assert isinstance(tool, vx.Tool)
    res = tool.run({"x": 1})
    assert res.status == "completed"


def test_evidence_alias_points_to_observation():
    assert vx.Evidence is vx.Observation
