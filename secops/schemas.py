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
    quick: bool = False


class RunValidationConfigUpdate(BaseModel):
    enabled: bool | None = None
    label: str | None = None


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
    fingerprint: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    reproduction_script: str = ""
    promoted_at: datetime | None = None
    reviewed_at: datetime | None = None
    reviewer_user_id: str | None = None
    disposition: str = "draft"


class FindingReviewCreate(BaseModel):
    disposition: str
    note: str = ""


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
    error: str = ""
    live: dict[str, Any] = Field(default_factory=dict)


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
    schema_version: str = ""
    parent_event_id: str | None = None
    phase: str = ""
    agent_role: str = ""
    target_ref: str = ""
    action_id: str = ""
    action_type: str = ""
    risk: str = "info"
    policy: dict[str, Any] = Field(default_factory=dict)
    validation: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    error: dict[str, Any] = Field(default_factory=dict)
    artifact_ids: list[str] = Field(default_factory=list)
    graph_delta_ids: list[str] = Field(default_factory=list)


class BusEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    branch_id: str
    seq: int
    turn_id: int
    agent: str
    type: str
    payload: dict[str, Any] = Field(validation_alias="payload_json")
    parent_turn_id: int | None = None
    caused_by_fact_ids: list[str] = Field(default_factory=list)
    content_hash: str = ""
    created_at: datetime


class WorkflowExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    workflow_kind: str
    status: str
    current_phase: str
    attempt_count: int
    blocked_reason: str
    error_class: str
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    started_at: datetime | None
    completed_at: datetime | None
    updated_at: datetime
    created_at: datetime


class WorkflowPhaseRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    workflow_id: str
    phase_name: str
    attempt: int
    status: str
    retry_class: str
    worker_id: str
    lease_expires_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    next_attempt_at: datetime | None
    input: dict[str, Any] = Field(validation_alias="input_json")
    output: dict[str, Any] = Field(validation_alias="output_json")
    error: dict[str, Any] = Field(validation_alias="error_json")
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    created_at: datetime
    updated_at: datetime


class RunCheckpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    workflow_id: str | None
    phase_name: str
    phase_attempt: int
    checkpoint_key: str
    status: str
    payload: dict[str, Any] = Field(validation_alias="payload_json")
    is_latest: bool
    created_at: datetime
    updated_at: datetime


class WorkerLeaseRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    workflow_id: str | None
    phase_name: str
    phase_run_id: str | None
    worker_id: str
    status: str
    heartbeat_at: datetime
    lease_expires_at: datetime
    released_at: datetime | None
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    created_at: datetime
    updated_at: datetime


class RunMetricRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    workflow_id: str | None
    phase_name: str
    metric_name: str
    metric_value: float
    metric_unit: str
    tags: list[str]
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    created_at: datetime


class WorkerRuntimeStatusRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    worker_id: str
    hostname: str
    pid: int
    status: str
    current_run_id: str
    current_phase: str
    lease_expires_at: datetime | None
    heartbeat_at: datetime
    last_error: str
    metadata: dict[str, Any] = Field(validation_alias="metadata_json")
    started_at: datetime
    updated_at: datetime


class WorkflowStateRead(BaseModel):
    run_id: str
    workflow: WorkflowExecutionRead | None = None
    phases: list[WorkflowPhaseRunRead] = Field(default_factory=list)
    leases: list[WorkerLeaseRead] = Field(default_factory=list)
    workers: list[WorkerRuntimeStatusRead] = Field(default_factory=list)
    blocked_reasons: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)


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
    author: str = "operator"  # ignored; author is derived from the session (PRA-044)
    applies_to: str = "run"
    classification: str = "unrestricted"  # unrestricted|internal|sensitive


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
    phase: dict[str, Any] = Field(default_factory=dict)
    tasks: list[TaskRead]
    agents: list[AgentSessionRead]
    approvals: list[ApprovalRead]


class AttackGraphNodeRead(BaseModel):
    id: str
    type: str
    key: str
    label: str
    source_kind: str = ""
    source_id: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackGraphEdgeRead(BaseModel):
    id: str
    source: str
    target: str
    type: str
    source_kind: str = ""
    source_id: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackGraphRead(BaseModel):
    run_id: str
    summary: dict[str, Any] = Field(default_factory=dict)
    nodes: list[AttackGraphNodeRead] = Field(default_factory=list)
    edges: list[AttackGraphEdgeRead] = Field(default_factory=list)


class TerminalRead(BaseModel):
    run_id: str
    content: str
    last_sequence: int = 0


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
    report_json_path: str | None = None
    comprehensive_report_path: str | None = None
    comprehensive_report_json_path: str | None = None
    artifact_index_path: str | None = None
    timeline_csv_path: str | None = None
    executive_summary: str = ""


class BrowserStateRead(BaseModel):
    run_id: str
    status: str = "idle"
    entry_url: str = ""
    current_url: str = ""
    authenticated: str = "not_attempted"
    pages_visited: int = 0
    routes_discovered: int = 0
    blocked_actions: list[str] = Field(default_factory=list)
    network_summary: dict[str, Any] = Field(default_factory=dict)
    route_edges: list[dict[str, Any]] = Field(default_factory=list)
    forms: list[dict[str, Any]] = Field(default_factory=list)
    session_summary: dict[str, Any] = Field(default_factory=dict)
    auth_transitions: list[dict[str, Any]] = Field(default_factory=list)
    dom_diffs: list[dict[str, Any]] = Field(default_factory=list)
    js_signals: list[dict[str, Any]] = Field(default_factory=list)
    route_hints: list[dict[str, Any]] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)


class RunPhaseRead(BaseModel):
    current: str
    completed: list[str] = Field(default_factory=list)
    pending: list[str] = Field(default_factory=list)
    updated_at: str = ""
    reason: str = ""
    history: list[dict[str, Any]] = Field(default_factory=list)


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
    editable: bool = False


class SkillPackCreate(BaseModel):
    id: str
    name: str
    summary: str = ""
    roles: list[str] = Field(default_factory=list)
    modes: list[str] = Field(default_factory=list)
    execution_level: str = "advisory"
    safety_level: str = "active"
    tags: list[str] = Field(default_factory=list)
    requires_scope: bool = True
    forbidden: list[str] = Field(default_factory=list)
    body: str


class SkillPackUpdate(BaseModel):
    name: str | None = None
    summary: str | None = None
    roles: list[str] | None = None
    modes: list[str] | None = None
    execution_level: str | None = None
    safety_level: str | None = None
    tags: list[str] | None = None
    requires_scope: bool | None = None
    forbidden: list[str] | None = None
    body: str | None = None
    version: int | None = None


class SkillRegistryReloadRead(BaseModel):
    count: int
    skills: list[SkillPackRead]


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
    facts: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    learning_hits: list[str] = Field(default_factory=list)
    operator_notes: list[str] = Field(default_factory=list)


class AttackChainRead(BaseModel):
    id: str
    name: str
    score: int
    status: str
    steps: list[dict[str, Any]]
    mitre_ids: list[str]
    notes: str
    provenance: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class PlanningBundleRead(BaseModel):
    run_id: str
    workflow_status: str
    best_vectors: list[VectorRead]
    best_chains: list[AttackChainRead]
    ranking_rationale: list[dict[str, Any]]
    missing_evidence: list[str]


class ReplayStateRead(BaseModel):
    run_id: str
    status: str
    phase_history: list[dict[str, Any]] = Field(default_factory=list)
    events: list[RunEventRead] = Field(default_factory=list)
    report_path: str = ""
    report_json_path: str = ""
    summary: dict[str, Any] = Field(default_factory=dict)
    manifest: dict[str, Any] = Field(default_factory=dict)


class FindingPromotionCreate(BaseModel):
    source_kind: str
    source_id: str
    title: str = ""
    severity: str = ""
    status: str = "draft"
    summary: str = ""
    evidence: str = ""
    reproduction: str = ""
    remediation: str = ""
    confidence: float | None = None


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
    worker: dict[str, Any] = Field(default_factory=dict)
    workers: list[dict[str, Any]] = Field(default_factory=list)
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


class RunProviderRouteCreate(BaseModel):
    provider_id: str = ""
