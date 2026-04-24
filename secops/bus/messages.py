"""Typed agent-message bus schemas (vantix.event.v2).

These are the envelope and payload types the Phase-1 planner / executor /
evaluator loop will use to talk over the durable bus. They live in their
own module so they can be imported by tests, the router, and the UI
without pulling in the execution service.

Reuses shapes from ``secops.agents.contracts`` where they already exist
(``ActionProposal`` → ``ProposedAction`` here is a near-alias kept
separately so the bus layer owns its own vocabulary and doesn't whiplash
when the agents package evolves).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


AgentRole = Literal[
    "planner",
    "executor",
    "evaluator",
    "specialist:recon",
    "specialist:web",
    "specialist:exploit",
    "specialist:cred",
    "specialist:browser",
    "specialist:report",
]

MessageType = Literal["plan", "action", "observation", "critique", "policy_decision"]

PolicyVerdict = Literal["allow", "deny", "approve", "block", "require_approval"]

RiskLevel = Literal["info", "low", "medium", "high", "critical"]


class ProposedAction(BaseModel):
    """An action the planner has queued for the executor to dispatch."""

    model_config = ConfigDict(extra="forbid")

    action_type: str
    objective: str
    target_ref: str = ""
    risk: RiskLevel = "low"
    agent_role: str = ""
    inputs: dict[str, Any] = Field(default_factory=dict)
    required_evidence: list[str] = Field(default_factory=list)
    rationale: str = ""


class Plan(BaseModel):
    """Ordered list of proposed actions emitted by the planner for one turn."""

    model_config = ConfigDict(extra="forbid")

    turn_id: int
    rationale: str = ""
    actions: list[ProposedAction] = Field(default_factory=list)
    budget_tokens: int | None = None
    budget_wall_seconds: int | None = None


class Observation(BaseModel):
    """Executor report of what a dispatched action produced."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    action_type: str
    status: Literal["completed", "failed", "blocked", "skipped"]
    summary: str = ""
    output_ref: str = ""
    artifact_ids: list[str] = Field(default_factory=list)
    fact_ids: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    error: dict[str, Any] = Field(default_factory=dict)


class Critique(BaseModel):
    """Evaluator assessment of a batch of observations; feeds the next plan."""

    model_config = ConfigDict(extra="forbid")

    turn_id: int
    observations: list[str] = Field(default_factory=list, description="Observation action_ids reviewed")
    should_replan: bool = True
    confidence: float = 0.0
    new_hypotheses: list[str] = Field(default_factory=list)
    refuted_hypotheses: list[str] = Field(default_factory=list)
    notes: str = ""


class PolicyDecision(BaseModel):
    """Decision emitted by capability / plan-review / action-gate phases."""

    model_config = ConfigDict(extra="forbid")

    phase: Literal["capability", "plan_review", "action_gate"]
    verdict: PolicyVerdict
    reason: str = ""
    matched_rule: str = ""
    audit: dict[str, Any] = Field(default_factory=dict)
    subject_ref: str = Field("", description="action_id or plan turn_id this decision targets")


PayloadT = Plan | ProposedAction | Observation | Critique | PolicyDecision


class BusEnvelope(BaseModel):
    """vantix.event.v2 envelope for every persisted bus message."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2] = 2
    kind: Literal["vantix.event.v2"] = "vantix.event.v2"
    run_id: str
    branch_id: str = "main"
    turn_id: int
    agent: AgentRole
    type: MessageType
    payload: dict[str, Any]
    parent_turn_id: int | None = None
    caused_by_fact_ids: list[str] = Field(default_factory=list)
    content_hash: str = ""
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
