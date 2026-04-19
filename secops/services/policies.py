from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Iterable

from secops.config import settings
from secops.models import WorkspaceRun


@dataclass(slots=True)
class PolicyDecision:
    verdict: str
    reason: str
    audit: bool = False


@dataclass(slots=True)
class SubprocessRecord:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    error_class: str


SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{10,}"),
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*([^\s]+)"),
]


class ExecutionPolicyService:
    def evaluate(self, run: WorkspaceRun, *, action_kind: str) -> PolicyDecision:
        if run.status in {"cancelled", "failed"}:
            return PolicyDecision(verdict="block", reason=f"run is {run.status}")
        if action_kind == "script":
            if not settings.enable_script_execution:
                return PolicyDecision(verdict="block", reason="script execution disabled")
            return PolicyDecision(verdict="allow_with_audit", reason="script execution allowed", audit=True)
        if action_kind == "codex":
            if not settings.enable_codex_execution:
                return PolicyDecision(verdict="require_approval", reason="codex execution disabled", audit=True)
            return PolicyDecision(verdict="allow_with_audit", reason="codex execution allowed", audit=True)
        return PolicyDecision(verdict="allow", reason="default policy")

    def run_subprocess(
        self,
        command: list[str],
        *,
        timeout_seconds: int = 120,
        redactions: Iterable[str] | None = None,
    ) -> SubprocessRecord:
        if not command:
            return SubprocessRecord(command=[], returncode=0, stdout="", stderr="", timed_out=False, error_class="")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout_seconds)
            stdout = self._redact(result.stdout or "", redactions=redactions)
            stderr = self._redact(result.stderr or "", redactions=redactions)
            error_class = "" if result.returncode == 0 else "nonzero_exit"
            return SubprocessRecord(
                command=command,
                returncode=result.returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=False,
                error_class=error_class,
            )
        except subprocess.TimeoutExpired as exc:
            return SubprocessRecord(
                command=command,
                returncode=124,
                stdout=self._redact((exc.stdout or "") if isinstance(exc.stdout, str) else "", redactions=redactions),
                stderr=self._redact((exc.stderr or "") if isinstance(exc.stderr, str) else "", redactions=redactions),
                timed_out=True,
                error_class="timeout",
            )
        except OSError as exc:
            return SubprocessRecord(command=command, returncode=127, stdout="", stderr=str(exc), timed_out=False, error_class="oserror")

    def _redact(self, text: str, *, redactions: Iterable[str] | None = None) -> str:
        if not text:
            return ""
        cleaned = text
        for pattern in SECRET_PATTERNS:
            cleaned = pattern.sub("[REDACTED]", cleaned)
        for token in redactions or []:
            if token:
                cleaned = cleaned.replace(token, "[REDACTED]")
        return cleaned
