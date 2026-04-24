from secops.agents.executor import ExecutorAgent
from secops.bus.messages import ProposedAction
from secops.tools.base import ToolResult
from secops.tools.registry import ToolRegistry


class _StubTool:
    name = "echo"

    def __init__(self, result: ToolResult):
        self._result = result

    def run(self, inputs):
        return self._result


class _ExplodeTool:
    name = "boom"

    def run(self, inputs):
        raise RuntimeError("kaboom")


def test_executor_dispatches_to_registered_tool():
    reg = ToolRegistry()
    reg.register(_StubTool(ToolResult(status="completed", summary="ok", metrics={"n": 1})))
    ex = ExecutorAgent(reg)
    obs = ex.execute(ProposedAction(action_type="echo", objective="", inputs={"k": "v"}))
    assert obs.status == "completed"
    assert obs.summary == "ok"
    assert obs.metrics["n"] == 1
    assert obs.action_id.startswith("act_")


def test_executor_missing_tool_returns_failure():
    ex = ExecutorAgent(ToolRegistry())
    obs = ex.execute(ProposedAction(action_type="nope", objective=""))
    assert obs.status == "failed"
    assert obs.error["reason"] == "tool_not_registered"


def test_executor_catches_exceptions():
    reg = ToolRegistry()
    reg.register(_ExplodeTool())
    ex = ExecutorAgent(reg)
    obs = ex.execute(ProposedAction(action_type="boom", objective=""))
    assert obs.status == "failed"
    assert obs.error["exception"] == "RuntimeError"
