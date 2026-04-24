"""ExecutorAgent — dispatches a ProposedAction to a Tool and returns an Observation."""

from __future__ import annotations

from uuid import uuid4

from secops.agents.base import BaseAgent
from secops.bus.messages import Observation, ProposedAction
from secops.tools.registry import ToolRegistry


class ExecutorAgent(BaseAgent):
    role = "executor"

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def execute(self, action: ProposedAction) -> Observation:
        action_id = f"act_{uuid4().hex[:12]}"
        tool = self._registry.get(action.action_type)
        if tool is None:
            return Observation(
                action_id=action_id,
                action_type=action.action_type,
                status="failed",
                summary=f"no tool registered for action_type={action.action_type!r}",
                error={"reason": "tool_not_registered"},
            )
        try:
            result = tool.run(dict(action.inputs))
        except Exception as exc:  # noqa: BLE001
            return Observation(
                action_id=action_id,
                action_type=action.action_type,
                status="failed",
                summary=str(exc),
                error={"reason": "tool_exception", "exception": type(exc).__name__},
            )
        return Observation(
            action_id=action_id,
            action_type=action.action_type,
            status=result.status,  # type: ignore[arg-type]
            summary=result.summary,
            output_ref=result.output_ref,
            artifact_ids=list(result.artifact_ids),
            fact_ids=list(result.fact_ids),
            metrics=dict(result.metrics),
            error=dict(result.error),
        )
