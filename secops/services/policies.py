from __future__ import annotations

import re
import subprocess
import time
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
    duration_seconds: float


SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{10,}"),
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*([^\s]+)"),
]


class ExecutionPolicyService:
    def evaluate(self, run: WorkspaceRun, *, action_kind: str) -> PolicyDecision:
        kind = (action_kind or "").strip().lower()
        if run.status in {"cancelled", "failed"}:
            return PolicyDecision(verdict="block", reason=f"run is {run.status}")
        if kind == "script":
            if not settings.enable_script_execution:
                return PolicyDecision(verdict="block", reason="script execution disabled")
            return PolicyDecision(verdict="allow_with_audit", reason="script execution allowed", audit=True)
        if kind == "codex":
            if not settings.enable_codex_execution:
                return PolicyDecision(verdict="require_approval", reason="codex execution disabled", audit=True)
            return PolicyDecision(verdict="allow_with_audit", reason="codex execution allowed", audit=True)
        if kind in {"write_action", "filesystem_write"}:
            if not settings.enable_write_execution:
                return PolicyDecision(verdict="require_approval", reason="write actions require approval", audit=True)
            return PolicyDecision(verdict="allow_with_audit", reason="write action allowed", audit=True)
        if kind in {"recon_high_noise", "exploit_validation"}:
            return PolicyDecision(verdict="require_approval", reason=f"{kind} requires operator approval", audit=True)
        if kind in {"external_network", "network"}:
            return PolicyDecision(verdict="allow_with_audit", reason="external network action audited", audit=True)
        return PolicyDecision(verdict="allow", reason="default policy")

    def run_subprocess(
        self,
        command: list[str],
        *,
        timeout_seconds: int = 120,
        redactions: Iterable[str] | None = None,
    ) -> SubprocessRecord:
        started = time.monotonic()
        if not command:
            return SubprocessRecord(command=[], returncode=0, stdout="", stderr="", timed_out=False, error_class="", duration_seconds=0.0)
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
                duration_seconds=max(0.0, time.monotonic() - started),
            )
        except subprocess.TimeoutExpired as exc:
            return SubprocessRecord(
                command=command,
                returncode=124,
                stdout=self._redact((exc.stdout or "") if isinstance(exc.stdout, str) else "", redactions=redactions),
                stderr=self._redact((exc.stderr or "") if isinstance(exc.stderr, str) else "", redactions=redactions),
                timed_out=True,
                error_class="timeout",
                duration_seconds=max(0.0, time.monotonic() - started),
            )
        except OSError as exc:
            return SubprocessRecord(
                command=command,
                returncode=127,
                stdout="",
                stderr=self._redact(str(exc), redactions=redactions),
                timed_out=False,
                error_class="oserror",
                duration_seconds=max(0.0, time.monotonic() - started),
            )

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
