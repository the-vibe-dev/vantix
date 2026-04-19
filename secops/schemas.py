from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EngagementCreate(BaseModel):
    name: str
    mode: str
    target: str = ""
    ruleset: str = ""
    notes: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EngagementRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    mode: str
    target: str
    ruleset: str
    status: str
    notes: str
    tags: list[str]
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    created_at: datetime
    updated_at: datetime


class RunCreate(BaseModel):
    engagement_id: str
    objective: str = ""
    target: str = ""
    services: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)


class RunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    engagement_id: str
    mode: str
    workspace_id: str
    status: str
    objective: str
    repo_path: str
    target: str
    config: dict[str, Any] = Field(validation_alias="config_json")
    resumed_from_run_id: str | None = None
    started_at: datetime
    updated_at: datetime


class RunControlResponse(BaseModel):
    run_id: str
    status: str
    message: str


class TaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    name: str
    description: str
    kind: str
    status: str
    sequence: int
    context: dict[str, Any] = Field(validation_alias="context_json")
    result: dict[str, Any] = Field(validation_alias="result_json")
    created_at: datetime
    updated_at: datetime


class ActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    task_id: str
    name: str
    tool: str
    command: str
    status: str
    parameters: dict[str, Any] = Field(validation_alias="parameters_json")
    result: dict[str, Any] = Field(validation_alias="result_json")
    output_text: str
    started_at: datetime
    completed_at: datetime | None


class ArtifactRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    action_id: str | None
    kind: str
    path: str
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    created_at: datetime


class MemoryEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    action_id: str | None
    classification: str
    source: str
    content: str
    tags: list[str]
    embedding_model: str
    embedding: list[float]
    created_at: datetime


class DenseMemoryCreate(BaseModel):
    mode: str = "checkpoint"
    session_id: str = ""
    run_id: str = ""
    agent: str = ""
    phase: str = ""
    objective: str = ""
    done: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    next_action: str = ""
    files: list[str] = Field(default_factory=list)
    facts: list[list[str]] = Field(default_factory=list)
    context: list[str] = Field(default_factory=list)


class DenseMemoryReceipt(BaseModel):
    ok: bool
    ts: str
    session_id: str
    run_id: str = ""
    seq: int
    paths: list[str]
    sha256: str


class MemoryHealthRead(BaseModel):
    ok: bool
    reason: str | None = None
    age_seconds: int | None = None
    stale_minutes: int | None = None
    latest: dict[str, Any] | None = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    title: str
    severity: str
    status: str
    summary: str
    evidence: str
    reproduction: str
    remediation: str
    confidence: float
    created_at: datetime


class ContextBundleRead(BaseModel):
    prompt_prefix: str
    startup_sources: list[dict[str, str]]
    learning_digest: str
    mode_profile: dict[str, Any]
    assembled_prompt: str


class CVESearchResponse(BaseModel):
    source: str
    query: str
    results: list[dict[str, Any]]


class RunEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    agent_session_id: str | None
    sequence: int
    event_type: str
    level: str
    message: str
    payload: dict[str, Any] = Field(validation_alias="payload_json")
    created_at: datetime


class ApprovalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    title: str
    detail: str
    status: str
    reason: str
    response_note: str
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    created_at: datetime
    updated_at: datetime


class ApprovalDecision(BaseModel):
    note: str = ""


class OperatorNoteCreate(BaseModel):
    content: str
    author: str = "operator"
    applies_to: str = "run"


class OperatorNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    content: str
    author: str
    applies_to: str
    created_at: datetime


class AgentSessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    role: str
    name: str
    status: str
    workspace_path: str
    prompt_path: str
    log_path: str
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    started_at: datetime
    updated_at: datetime
    completed_at: datetime | None


class FactRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    source: str
    kind: str
    value: str
    confidence: float
    tags: list[str]
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    created_at: datetime


class RunGraphRead(BaseModel):
    run_id: str
    status: str
    tasks: list[TaskRead]
    agents: list[AgentSessionRead]
    approvals: list[ApprovalRead]


class TerminalRead(BaseModel):
    run_id: str
    content: str


class RunLearningRead(BaseModel):
    run_id: str
    mode: str
    results: list[dict[str, Any]]


class RunMessageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    role: str
    author: str
    content: str
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    created_at: datetime


class ChatCreate(BaseModel):
    message: str
    run_id: str | None = None
    mode: str | None = None
    target: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChatResponse(BaseModel):
    run: RunRead
    message: RunMessageRead
    started: bool
    scheduler_status: str


class VectorCreate(BaseModel):
    title: str
    summary: str = ""
    source: str = "manual"
    confidence: float = 0.5
    severity: str = "info"
    status: str = "candidate"
    evidence: str = ""
    next_action: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class VectorRead(BaseModel):
    id: str
    title: str
    summary: str
    source: str
    confidence: float
    severity: str
    status: str
    evidence: str
    next_action: str
    metadata: dict[str, Any]
    created_at: datetime


class RunResultsRead(BaseModel):
    run_id: str
    status: str
    findings: list[FindingRead]
    artifacts: list[ArtifactRead]
    vectors: list[VectorRead]
    terminal_summary: str
    report_path: str | None = None


class SkillPackRead(BaseModel):
    id: str
    name: str
    version: int
    summary: str
    roles: list[str]
    modes: list[str]
    execution_level: str
    safety_level: str
    tags: list[str]
    requires_scope: bool
    forbidden: list[str]
    reason: str = ""


class RunSkillApplicationRead(BaseModel):
    agent_role: str
    skills: list[SkillPackRead]
    prompt_path: str


class AttackChainCreate(BaseModel):
    name: str
    score: int = 50
    status: str = "identified"
    steps: list[dict[str, Any]] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    notes: str = ""


class AttackChainRead(BaseModel):
    id: str
    name: str
    score: int
    status: str
    steps: list[dict[str, Any]]
    mitre_ids: list[str]
    notes: str
    created_at: datetime


class HandoffRead(BaseModel):
    run_id: str
    workspace_id: str
    mode: str
    status: str
    target: str
    objective: str
    scope: str
    phase: str
    services: list[dict[str, Any]]
    vectors: list[dict[str, Any]]
    validated_findings: list[dict[str, Any]]
    blocked_items: list[str]
    attack_chains: list[AttackChainRead]
    next_actions: list[str]


class SystemStatusRead(BaseModel):
    product: str
    version: str
    default_runtime: str
    codex: dict[str, Any]
    execution: dict[str, Any]
    runtime: dict[str, Any]
    artifacts: dict[str, Any]
    memory: dict[str, Any]
    cve_mcp: dict[str, Any]
    providers: dict[str, Any]
    installer: dict[str, Any] = Field(default_factory=dict)
    tooling: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str]


class ToolStatusRead(BaseModel):
    id: str
    name: str
    binaries: list[str]
    suites: list[str]
    method: str
    installed: bool
    binary: str = ""
    path: str = ""
    version: str = ""
    installable: bool = False
    allow_auto_install: bool = False
    last_result: dict[str, Any] = Field(default_factory=dict)


class ToolInstallCreate(BaseModel):
    tool_ids: list[str] = Field(default_factory=list)
    suite: str = ""
    apply: bool = True


class ToolInstallResultRead(BaseModel):
    tool_id: str
    method: str | None = None
    ok: bool
    status: str | None = None
    reason: str | None = None
    commands: list[list[str]] = Field(default_factory=list)
    path: str = ""
    version: str = ""
    output_tail: str = ""


class InstallerStateRead(BaseModel):
    ready: bool = False
    updated_at: str = ""
    state: dict[str, Any] = Field(default_factory=dict)


class ProviderConfigCreate(BaseModel):
    name: str
    provider_type: str
    base_url: str = ""
    default_model: str = ""
    enabled: bool = False
    secret: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderConfigRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    name: str
    provider_type: str
    base_url: str
    default_model: str
    enabled: bool
    has_key: bool = False
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    created_at: datetime
    updated_at: datetime
