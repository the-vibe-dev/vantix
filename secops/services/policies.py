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
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd)\s*[:=]\s*[^\s\"']{4,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gho_[A-Za-z0-9]{36}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"xox[pbaros]-[A-Za-z0-9-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-+/=]{8,}"),
    re.compile(r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END[^-]+-----"),
    re.compile(r"(?i)cookie:\s*[^\r\n]+"),
    re.compile(r"(?i)set-cookie:\s*[^\r\n]+"),
    re.compile(r"https?://[^\s:/@]+:[^\s@/]+@[^\s]+"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
]


class ExecutionPolicyService:
    def _approval_grants(self, run: WorkspaceRun) -> dict[str, int]:
        raw = (run.config_json or {}).get("approval_grants")
        if not isinstance(raw, dict):
            return {}
        grants: dict[str, int] = {}
        for key, value in raw.items():
            try:
                grants[str(key)] = int(value)
            except (TypeError, ValueError):
                continue
        return grants

    def _consume_grant(self, run: WorkspaceRun, kind: str) -> bool:
        grants = self._approval_grants(run)
        remaining = int(grants.get(kind, 0))
        if remaining <= 0:
            return False
        grants[kind] = remaining - 1
        run.config_json = {**(run.config_json or {}), "approval_grants": grants}
        return True

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
            if self._consume_grant(run, kind):
                return PolicyDecision(verdict="allow_with_audit", reason=f"{kind} operator-approved", audit=True)
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
        MAX_OUTPUT = 16 * 1024
        cleaned = text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + f"\n...[TRUNCATED {len(text) - MAX_OUTPUT} bytes]"
        for pattern in SECRET_PATTERNS:
            cleaned = pattern.sub("[REDACTED]", cleaned)
        for token in redactions or []:
            if token:
                cleaned = cleaned.replace(token, "[REDACTED]")
        return cleaned
