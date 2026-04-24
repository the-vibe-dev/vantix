"""vantix-sdk — public interfaces for extending Vantix.

Third parties write agents, tools, and policies against this package;
the internal ``secops.*`` modules provide the reference implementation
but are not part of the public contract.

Stable surface:
- ``Agent``, ``BaseAgent``, ``RunState`` — agent protocol.
- ``Tool``, ``ToolResult`` — tool adapter contract.
- ``Plan``, ``ProposedAction``, ``Observation``, ``Critique``,
  ``PolicyDecision``, ``BusEnvelope`` — typed messages.
- ``PlanReview`` — policy review verdict.
- ``Evidence`` — alias for Observation to keep naming aligned with
  plan §3.3 (extract public SDK surface).

Everything else under ``secops.*`` is private and may change without
notice. See plan §11.4 (Agent protocol) for the canonical contract.
"""

from __future__ import annotations

from secops.agents.base import Agent, BaseAgent, RunState
from secops.bus.messages import (
    BusEnvelope,
    Critique,
    Observation,
    Plan,
    PolicyDecision,
    ProposedAction,
)
from secops.policy.review import PlanReview
from secops.tools.base import Tool, ToolResult

# Observation ≡ Evidence for the SDK naming — an observation is the
# evidence the executor produced for a proposed action.
Evidence = Observation

__version__ = "0.1.0"

__all__ = [
    "Agent",
    "BaseAgent",
    "RunState",
    "Tool",
    "ToolResult",
    "Plan",
    "ProposedAction",
    "Observation",
    "Evidence",
    "Critique",
    "PolicyDecision",
    "BusEnvelope",
    "PlanReview",
    "__version__",
]
