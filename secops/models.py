from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from secops.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid4())


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    mode: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    ruleset: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(32), default="draft")
    notes: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    runs: Mapped[list["WorkspaceRun"]] = relationship(back_populates="engagement", cascade="all, delete-orphan")


class WorkspaceRun(Base):
    __tablename__ = "workspace_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    mode: Mapped[str] = mapped_column(String(64), index=True)
    workspace_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    objective: Mapped[str] = mapped_column(Text, default="")
    repo_path: Mapped[str] = mapped_column(String(512), default="")
    target: Mapped[str] = mapped_column(String(255), default="")
    config_json: Mapped[dict[str, Any]] = mapped_column("config", JSON, default=dict)
    resumed_from_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="runs")
    tasks: Mapped[list["Task"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    memory_events: Mapped[list["MemoryEvent"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    run_events: Mapped[list["RunEvent"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    approvals: Mapped[list["ApprovalRequest"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    operator_notes: Mapped[list["OperatorNote"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    agent_sessions: Mapped[list["AgentSession"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    facts: Mapped[list["Fact"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    messages: Mapped[list["RunMessage"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    workflows: Mapped[list["WorkflowExecution"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    workflow_phase_runs: Mapped[list["WorkflowPhaseRun"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    run_checkpoints: Mapped[list["RunCheckpoint"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    worker_leases: Mapped[list["WorkerLease"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    run_metrics: Mapped[list["RunMetric"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(64), default="generic")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    context_json: Mapped[dict[str, Any]] = mapped_column("context", JSON, default=dict)
    result_json: Mapped[dict[str, Any]] = mapped_column("result", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="tasks")
    actions: Mapped[list["Action"]] = relationship(back_populates="task", cascade="all, delete-orphan")


class Action(Base):
    __tablename__ = "actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    tool: Mapped[str] = mapped_column(String(128))
    command: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    parameters_json: Mapped[dict[str, Any]] = mapped_column("parameters", JSON, default=dict)
    result_json: Mapped[dict[str, Any]] = mapped_column("result", JSON, default=dict)
    output_text: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    task: Mapped[Task] = relationship(back_populates="actions")
    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="action")


class AgentSession(Base):
    __tablename__ = "agent_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    role: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    workspace_path: Mapped[str] = mapped_column(String(1024), default="")
    prompt_path: Mapped[str] = mapped_column(String(1024), default="")
    log_path: Mapped[str] = mapped_column(String(1024), default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    run: Mapped[WorkspaceRun] = relationship(back_populates="agent_sessions")


class RunEvent(Base):
    __tablename__ = "run_events"
    __table_args__ = (
        Index("ix_run_events_run_sequence", "run_id", "sequence"),
        Index("ix_run_events_run_created", "run_id", "created_at"),
        Index("ix_run_events_run_type_seq", "run_id", "event_type", "sequence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    agent_session_id: Mapped[str | None] = mapped_column(ForeignKey("agent_sessions.id"), nullable=True, index=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0, index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    level: Mapped[str] = mapped_column(String(32), default="info")
    message: Mapped[str] = mapped_column(Text, default="")
    payload_json: Mapped[dict[str, Any]] = mapped_column("payload", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="run_events")


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    reason: Mapped[str] = mapped_column(String(128), default="")
    response_note: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="approvals")


class OperatorNote(Base):
    __tablename__ = "operator_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    content: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(128), default="operator")
    applies_to: Mapped[str] = mapped_column(String(128), default="run")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="operator_notes")


class RunMessage(Base):
    __tablename__ = "run_messages"
    __table_args__ = (
        Index("ix_run_messages_run_created", "run_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    role: Mapped[str] = mapped_column(String(32), index=True)
    author: Mapped[str] = mapped_column(String(128), default="operator")
    content: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="messages")


class Fact(Base):
    __tablename__ = "facts"
    __table_args__ = (
        Index("ix_facts_run_kind_created", "run_id", "kind", "created_at"),
        Index("ix_facts_run_created", "run_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    source: Mapped[str] = mapped_column(String(128), default="")
    kind: Mapped[str] = mapped_column(String(64), index=True)
    value: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    validated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="facts")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    action_id: Mapped[str | None] = mapped_column(ForeignKey("actions.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64))
    path: Mapped[str] = mapped_column(String(1024))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="artifacts")
    action: Mapped[Action | None] = relationship(back_populates="artifacts")


class MemoryEvent(Base):
    __tablename__ = "memory_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    action_id: Mapped[str | None] = mapped_column(ForeignKey("actions.id"), nullable=True, index=True)
    classification: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(255), default="")
    content: Mapped[str] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    embedding_model: Mapped[str] = mapped_column(String(128), default="")
    embedding: Mapped[list[float]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="memory_events")


class LearningItem(Base):
    __tablename__ = "learning_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mode: Mapped[str] = mapped_column(String(64), default="")
    category: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text, default="")
    target_doc: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(32), default="candidate")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntelSource(Base):
    __tablename__ = "intel_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    source_type: Mapped[str] = mapped_column(String(64), default="api")
    url: Mapped[str] = mapped_column(String(1024), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    cursor_json: Mapped[dict[str, Any]] = mapped_column("cursor", JSON, default=dict)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    intel_records: Mapped[list["VulnerabilityIntel"]] = relationship(back_populates="source", cascade="all, delete-orphan")


class VulnerabilityIntel(Base):
    __tablename__ = "vulnerability_intel"
    __table_args__ = (UniqueConstraint("source_id", "external_id", name="uq_vulnerability_intel_source_external"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("intel_sources.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(String(1024), default="")
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default="")
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    epss: Mapped[float] = mapped_column(Float, default=0.0)
    epss_percentile: Mapped[float] = mapped_column(Float, default=0.0)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    scanner_template_available: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    source: Mapped[IntelSource] = relationship(back_populates="intel_records")
    references: Mapped[list["VulnerabilityIntelReference"]] = relationship(back_populates="intel", cascade="all, delete-orphan")


class VulnerabilityIntelReference(Base):
    __tablename__ = "vulnerability_intel_references"
    __table_args__ = (UniqueConstraint("intel_id", "reference_type", "reference_value", name="uq_vuln_intel_reference"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    intel_id: Mapped[str] = mapped_column(ForeignKey("vulnerability_intel.id"), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    reference_type: Mapped[str] = mapped_column(String(64), default="url", index=True)
    reference_value: Mapped[str] = mapped_column(String(1024), default="", index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    intel: Mapped[VulnerabilityIntel] = relationship(back_populates="references")


class ProviderConfig(Base):
    __tablename__ = "provider_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    provider_type: Mapped[str] = mapped_column(String(64), index=True)
    base_url: Mapped[str] = mapped_column(String(1024), default="")
    default_model: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted_secret: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class WorkflowExecution(Base):
    __tablename__ = "workflow_executions"
    __table_args__ = (
        Index("ix_workflow_executions_run_status", "run_id", "status"),
        Index("ix_workflow_executions_status_updated", "status", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    workflow_kind: Mapped[str] = mapped_column(String(64), default="vantix-run")
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    current_phase: Mapped[str] = mapped_column(String(64), default="context-bootstrap")
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    blocked_reason: Mapped[str] = mapped_column(String(255), default="")
    error_class: Mapped[str] = mapped_column(String(64), default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="workflows")
    phase_runs: Mapped[list["WorkflowPhaseRun"]] = relationship(back_populates="workflow", cascade="all, delete-orphan")
    checkpoints: Mapped[list["RunCheckpoint"]] = relationship(back_populates="workflow", cascade="all, delete-orphan")
    leases: Mapped[list["WorkerLease"]] = relationship(back_populates="workflow", cascade="all, delete-orphan")
    metrics: Mapped[list["RunMetric"]] = relationship(back_populates="workflow", cascade="all, delete-orphan")


class WorkflowPhaseRun(Base):
    __tablename__ = "workflow_phase_runs"
    __table_args__ = (
        UniqueConstraint("workflow_id", "phase_name", "attempt", name="uq_workflow_phase_attempt"),
        Index("ix_workflow_phase_runs_run_phase", "run_id", "phase_name"),
        Index("ix_workflow_phase_runs_claim", "status", "lease_expires_at"),
        Index("ix_workflow_phase_runs_latest", "workflow_id", "phase_name", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    workflow_id: Mapped[str] = mapped_column(ForeignKey("workflow_executions.id"), index=True)
    phase_name: Mapped[str] = mapped_column(String(64), index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    retry_class: Mapped[str] = mapped_column(String(32), default="none")
    worker_id: Mapped[str] = mapped_column(String(64), default="")
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    input_json: Mapped[dict[str, Any]] = mapped_column("input", JSON, default=dict)
    output_json: Mapped[dict[str, Any]] = mapped_column("output", JSON, default=dict)
    error_json: Mapped[dict[str, Any]] = mapped_column("error", JSON, default=dict)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="workflow_phase_runs")
    workflow: Mapped[WorkflowExecution] = relationship(back_populates="phase_runs")


class RunCheckpoint(Base):
    __tablename__ = "run_checkpoints"
    __table_args__ = (
        Index("ix_run_checkpoints_run_phase_latest", "run_id", "phase_name", "is_latest"),
        Index("ix_run_checkpoints_lookup", "workflow_id", "phase_name", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    workflow_id: Mapped[str | None] = mapped_column(ForeignKey("workflow_executions.id"), nullable=True, index=True)
    phase_name: Mapped[str] = mapped_column(String(64), index=True)
    phase_attempt: Mapped[int] = mapped_column(Integer, default=1)
    checkpoint_key: Mapped[str] = mapped_column(String(128), default="state")
    status: Mapped[str] = mapped_column(String(32), default="ready")
    payload_json: Mapped[dict[str, Any]] = mapped_column("payload", JSON, default=dict)
    is_latest: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="run_checkpoints")
    workflow: Mapped[WorkflowExecution | None] = relationship(back_populates="checkpoints")


class WorkerLease(Base):
    __tablename__ = "worker_leases"
    __table_args__ = (
        Index("ix_worker_leases_status_expiry", "status", "lease_expires_at"),
        Index("ix_worker_leases_worker_heartbeat", "worker_id", "heartbeat_at"),
        Index("ix_worker_leases_run_phase", "run_id", "phase_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    workflow_id: Mapped[str | None] = mapped_column(ForeignKey("workflow_executions.id"), nullable=True, index=True)
    phase_name: Mapped[str] = mapped_column(String(64), index=True)
    phase_run_id: Mapped[str | None] = mapped_column(ForeignKey("workflow_phase_runs.id"), nullable=True, index=True)
    worker_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="worker_leases")
    workflow: Mapped[WorkflowExecution | None] = relationship(back_populates="leases")


class RunMetric(Base):
    __tablename__ = "run_metrics"
    __table_args__ = (
        Index("ix_run_metrics_run_metric", "run_id", "metric_name"),
        Index("ix_run_metrics_workflow_phase", "workflow_id", "phase_name"),
        Index("ix_run_metrics_created", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    workflow_id: Mapped[str | None] = mapped_column(ForeignKey("workflow_executions.id"), nullable=True, index=True)
    phase_name: Mapped[str] = mapped_column(String(64), default="")
    metric_name: Mapped[str] = mapped_column(String(64), index=True)
    metric_value: Mapped[float] = mapped_column(Float, default=0.0)
    metric_unit: Mapped[str] = mapped_column(String(32), default="")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[WorkspaceRun] = relationship(back_populates="run_metrics")
    workflow: Mapped[WorkflowExecution | None] = relationship(back_populates="metrics")


class WorkerRuntimeStatus(Base):
    __tablename__ = "worker_runtime_status"
    __table_args__ = (
        Index("ix_worker_runtime_status_heartbeat", "heartbeat_at"),
        Index("ix_worker_runtime_status_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    worker_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    pid: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="idle")
    current_run_id: Mapped[str] = mapped_column(String(36), default="")
    current_phase: Mapped[str] = mapped_column(String(64), default="")
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_run_fingerprint", "run_id", "fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("workspace_runs.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(32), default="info")
    status: Mapped[str] = mapped_column(String(32), default="candidate")
    summary: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    reproduction: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    reproduction_script: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewer_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    disposition: Mapped[str] = mapped_column(String(32), default="draft", nullable=False)

    run: Mapped[WorkspaceRun] = relationship(back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_route_created", "route", "created_at"),
        Index("ix_audit_log_actor_created", "actor", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    actor: Mapped[str] = mapped_column(String(128), default="")
    method: Mapped[str] = mapped_column(String(16), default="")
    route: Mapped[str] = mapped_column(String(255), default="")
    object_id: Mapped[str] = mapped_column(String(128), default="")
    verdict: Mapped[str] = mapped_column(String(32), default="")
    remote_addr: Mapped[str] = mapped_column(String(64), default="")
    payload_json: Mapped[dict[str, Any]] = mapped_column("payload", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), default="operator", index=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_user_sessions_user_active", "user_id", "revoked"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    remote_addr: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
