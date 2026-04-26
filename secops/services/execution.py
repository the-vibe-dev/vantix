from __future__ import annotations

import base64
import hashlib
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import subprocess
import time
from typing import Any
from urllib import request as urlrequest
from urllib import error as urlerror
from urllib.parse import quote, urlencode, urljoin, urlparse

from sqlalchemy import select

from secops.config import settings
from secops.db import SessionLocal
from secops.models import (
    Action,
    AgentSession,
    ApprovalRequest,
    Artifact,
    Fact,
    Finding,
    OperatorNote,
    RunMessage,
    Task,
    WorkspaceRun,
)
from secops.mode_profiles import get_mode_profile
from secops.services.codex_runner import CodexRunner
from secops.services.context_builder import ContextBuilder, sanitize_prompt_text
from secops.services.browser_runtime import BrowserRuntimeService
from secops.services.cve_search import CVESearchService
from secops.services.events import RunEventService
from secops.services.exploit_validation import ExploitValidationService
from secops.services.fingerprint import fingerprint_from_meta
from secops.services.learning import LearningService
from secops.services.memory_writer import DenseMemoryRecord, MemoryWriteService
from secops.services.policies import ExecutionPolicyService
from secops.services.reporting import ReportingService
from secops.services.source_intake import SourceIntakeService
from secops.services.storage import StorageLayout
from secops.services.worker_runtime import worker_runtime
from secops.services.workflows.engine import WorkflowEngine
from secops.execution.constants import (
    DEFAULT_VALIDATION_CONFIG,
    HIGH_RISK_RISK_TAGS,
    RISK_TAG_PATTERNS,
    ROLE_DISPLAY_NAMES,
    TASK_METADATA,
)
from secops.execution.decision import DecisionMixin
from secops.execution.http_browser import HttpBrowserMixin
from secops.execution.phases.browser import BrowserPhaseMixin
from secops.execution.phases.cve import CvePhaseMixin
from secops.execution.phases.recon import ReconPhaseMixin
from secops.execution.phases.report import ReportPhaseMixin
from secops.execution.phases.simple import SimplePhasesMixin
from secops.execution.phases.source import SourceAnalysisPhaseMixin
from secops.execution.runners import RunnersMixin
from secops.execution.scope import ScopeMixin
from secops.execution.session import SessionMixin
from secops.execution.validation import ValidationMixin

# Constants moved to secops.execution.constants.
# ORCHESTRATOR_REFUSAL_MARKERS lives in secops.llm.session (its only consumer).


class PhaseBlockedError(Exception):
    pass


class ExecutionManager(
    SimplePhasesMixin,
    ReportPhaseMixin,
    SourceAnalysisPhaseMixin,
    ReconPhaseMixin,
    CvePhaseMixin,
    BrowserPhaseMixin,
    RunnersMixin,
    DecisionMixin,
    HttpBrowserMixin,
    ValidationMixin,
    SessionMixin,
    ScopeMixin,
):
    def __init__(self) -> None:
        self.events = RunEventService()
        self.nas = StorageLayout()
        self.learning = LearningService()
        self.cve = CVESearchService()
        self.browser = BrowserRuntimeService()
        self.memory = MemoryWriteService()
        self.policies = ExecutionPolicyService()
        self.reporting = ReportingService()
        self.source_intake = SourceIntakeService()
        self.workflow_engine = WorkflowEngine()
        self.worker_runtime = worker_runtime

    def start(self, run_id: str) -> str:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None:
                return "Run not found"
            self.workflow_engine.enqueue_run(db, run)
            self.events.emit(db, run.id, "run_status", "Run queued", payload={"status": "queued"})
            self._write_memory(db, run, mode="startup", phase="run-queued", done=["run queued"], next_action="worker claim")
            db.commit()
        self.worker_runtime.ensure_running(self)
        return "Run queued"

    def pause(self, run_id: str) -> str:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None:
                return "Run not found"
            self.workflow_engine.block_run(db, run, "paused-by-operator")
            self.events.emit(db, run.id, "run_status", "Run paused by operator", payload={"status": run.status}, level="warning")
            self._create_approval(
                db,
                run.id,
                title="Run paused",
                detail="Operator requested pause. Add a note and use retry/replan/resume.",
                reason="operator-pause",
            )
            self._write_memory(db, run, mode="handoff", phase="pause", issues=["operator pause"], next_action="add operator note, then retry or replan")
            db.commit()
        return "Pause requested"

    def cancel(self, run_id: str) -> str:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None:
                return "Run not found"
            self.workflow_engine.cancel_run(db, run, reason="cancelled-by-operator")
            self.events.emit(db, run.id, "run_status", "Run cancelled", payload={"status": run.status}, level="warning")
            self._write_memory(db, run, mode="handoff", phase="cancel", issues=["run cancelled"], next_action="review latest events before resuming")
            db.commit()
        return "Cancel requested"

    def execute_phase(self, run_id: str, phase_name: str) -> dict:
        handlers = {
            "context-bootstrap": self._phase_context,
            "source-intake": self._phase_source_intake,
            "source-analysis": self._phase_source_analysis,
            "learning-recall": self._phase_learning,
            "recon-sidecar": self._phase_recon,
            "browser-assessment": self._phase_browser,
            "cve-analysis": self._phase_cve,
            "orchestrate": self._phase_orchestrate,
            "learn-ingest": self._phase_learn_ingest,
            "report": self._phase_report,
        }
        handler = handlers.get(phase_name)
        if handler is None:
            raise ValueError(f"Unknown phase: {phase_name}")
        handler(run_id)
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None:
                raise ValueError(f"Run not found: {run_id}")
            if run.status == "blocked":
                raise PhaseBlockedError(f"Run blocked during phase {phase_name}")
            if run.status == "failed":
                raise RuntimeError(f"Run failed during phase {phase_name}")
        return {"phase": phase_name, "status": "completed"}

    def _check_controls(self, db, run: WorkspaceRun) -> bool:
        return run.status not in {"blocked", "cancelled", "failed"}


execution_manager = ExecutionManager()
