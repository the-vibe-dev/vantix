"""Shared constants for the decomposed ExecutionManager mixins."""
from __future__ import annotations

ORACLE_ENDPOINT_MARKERS = (
    "/api/challenges",
    "/api/challenge",
    "/rest/challenges",
    "/api/score-board",
    "/api/scoreboard",
    "/score-board",
    "/scoreboard",
)

DEFAULT_VALIDATION_CONFIG = {
    "risk_mode": "always_attempt",
    "max_requests_per_vector": 1,
    "request_timeout_seconds": 8,
    "allow_state_mutation": True,
    "allow_availability_tests": True,
    "allow_local_file_read_checks": True,
    "allow_persistence_adjacent_checks": True,
    "high_risk_surfaces": {
        "enabled": True,
        "label": "High Risk Surfaces",
    },
}

RISK_TAG_PATTERNS = (
    ("availability-impact", ("danger zone", "potentially harmful", "dos", "denial of service", "resource exhaustion", "bomb", "out of memory", "maximum call stack", "availability")),
    ("state-mutation", ("post ", "patch ", "put ", "delete ", "created", "modified", "mutation", "tamper", "upgrade", "checkout", "registration", "product creation", "review update")),
    ("server-local-read", ("file read", "local file", "etc/passwd", "system.ini", "xxe", "external entity", "filesystem", "local file read")),
    ("persistence-adjacent", ("stored xss", "persisted xss", "persistent", "review", "feedback", "profile", "upload")),
    ("rce-adjacent", ("rce", "remote code", "command execution", "ssti", "template injection", "sandbox escape")),
    ("credential-exposure", ("credential", "password", "hash", "token", "jwt", "secret", "api key", "bearer")),
    ("authz-bypass", ("idor", "authorization", "access control", "privilege", "admin", "role", "object-level", "bypass")),
)

HIGH_RISK_RISK_TAGS = {
    "availability-impact",
    "state-mutation",
    "server-local-read",
    "persistence-adjacent",
    "rce-adjacent",
}

ROLE_DISPLAY_NAMES = {
    "orchestrator": "Orchestrator",
    "recon": "Vantix Recon",
    "browser": "Browser Analyst",
    "knowledge_base": "Knowledge Base",
    "vector_store": "Vector Store",
    "researcher": "Researcher",
    "developer": "Developer",
    "executor": "Executor",
    "reporter": "Vantix Report",
}

TASK_METADATA = {
    "context-bootstrap": ("Context Bootstrap", "Assemble workflow context, prompts, and normalized run state."),
    "source-intake": ("Source Intake", "Resolve source input for white-box analysis."),
    "source-analysis": ("Source Analysis", "Run source-level analysis and extract findings."),
    "learning-recall": ("Knowledge Recall", "Load dense memory, learning hits, tool guidance, and prior cases."),
    "recon-sidecar": ("Vantix Recon", "Collect low-noise service, port, and target facts."),
    "browser-assessment": ("Browser Assessment", "Explore in-scope web application behavior and capture evidence."),
    "cve-analysis": ("Vulnerability Research", "Query CVE, exploit, and vulnerability intelligence."),
    "orchestrate": ("Orchestrator Planning", "Select next action and branch between validation, execution, or report."),
    "learn-ingest": ("Execution Review", "Ingest execution evidence and learning artifacts."),
    "report": ("Vantix Report", "Summarize evidence, findings, and operator-ready report output."),
    "flow-initialization": ("Orchestrator", "Normalize target, objective, scope, and run state."),
    "vantix-recon": ("Vantix Recon", "Collect low-noise service, port, and target facts."),
    "knowledge-load": ("Knowledge Base", "Load dense memory, learning hits, tool guidance, and prior cases."),
    "vector-store": ("Vector Store", "Rank similar cases and candidate attack patterns."),
    "research": ("Researcher", "Query CVE, exploit, and vulnerability intelligence."),
    "planning": ("Orchestrator Planning", "Select next action and branch between recon, development, execution, or report."),
    "development": ("Developer", "Prepare validation helpers, payload notes, or exploit implementation guidance."),
    "execution": ("Executor", "Run the selected vector through current execution controls."),
    "reporting": ("Vantix Report", "Summarize evidence, artifacts, validated findings, and next steps."),
}
