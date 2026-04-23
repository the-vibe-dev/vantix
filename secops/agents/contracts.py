from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


RiskLevel = Literal["info", "low", "medium", "high", "critical"]
ValidationStatus = Literal["not_applicable", "validated", "rejected", "inconclusive"]
ActionStatus = Literal["proposed", "allowed", "blocked", "approval_required", "running", "completed", "failed"]


class ActionProposal(BaseModel):
    """A typed action request before policy evaluation and execution."""

    action_type: str
    objective: str
    target_ref: str = ""
    risk: RiskLevel = "low"
    phase: str = ""
    agent_role: str = ""
    inputs: dict[str, Any] = Field(default_factory=dict)
    required_evidence: list[str] = Field(default_factory=list)
    rationale: str = ""


class ActionResult(BaseModel):
    """The normalized result of a tool or agent action."""

    action_id: str = ""
    action_type: str
    status: ActionStatus
    summary: str = ""
    output_ref: str = ""
    artifact_ids: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    error: dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    """Proof state for a candidate vector or finding."""

    status: ValidationStatus
    reason: str = ""
    finding_id: str | None = None
    source_id: str = ""
    proof_artifact_ids: list[str] = Field(default_factory=list)
    negative_evidence_ids: list[str] = Field(default_factory=list)
    signal: dict[str, Any] = Field(default_factory=dict)

