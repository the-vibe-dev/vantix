from __future__ import annotations

import re
import subprocess
import time

from secops.config import settings
from secops.db import SessionLocal
from secops.models import WorkspaceRun


class RunnersMixin:
    """Subprocess execution, terminal-stream emission, nmap parsing.

    Extracted from ExecutionManager. Relies on ``self.events``, ``self.policies``
    from peer mixins / __init__.
    """

    def _emit_terminal_excerpt(
        self,
        db,
        *,
        run_id: str,
        output: str,
        agent_session_id: str,
        agent: str,
        max_lines: int = 120,
    ) -> None:
        lines = [line for line in output.splitlines() if line.strip()]
        if not lines:
            self.events.emit(
                db,
                run_id,
                "terminal",
                f"[{agent}] no output",
                payload={"agent": agent},
                agent_session_id=agent_session_id,
            )
            return
        for line in lines[:max_lines]:
            self.events.emit(
                db,
                run_id,
                "terminal",
                line,
                payload={"agent": agent},
                agent_session_id=agent_session_id,
            )
        if len(lines) > max_lines:
            self.events.emit(
                db,
                run_id,
                "terminal",
                f"[{agent}] output truncated ({len(lines) - max_lines} lines omitted)",
                payload={"agent": agent},
                agent_session_id=agent_session_id,
            )

    def _run_command(self, command: list[str], log_path: str, *, run_id: str | None = None) -> str:
        if not command:
            return ""
        if run_id is not None:
            with SessionLocal() as db:
                run = db.get(WorkspaceRun, run_id)
                if run is None:
                    return "Run not found for command execution.\n"
                decision = self.policies.evaluate(run, action_kind="script")
        else:
            decision = None
        if decision is not None:
            if decision.verdict in {"block", "require_approval"}:
                return f"Command blocked by policy: {decision.reason}\n"
        started = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        timed_out = False
        cancelled = False
        try:
            while True:
                try:
                    stdout, stderr = process.communicate(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    if run_id:
                        with SessionLocal() as db:
                            run = db.get(WorkspaceRun, run_id)
                            if run is None or run.status in {"cancelled", "failed"}:
                                cancelled = True
                                process.terminate()
                                try:
                                    stdout, stderr = process.communicate(timeout=3)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                    stdout, stderr = process.communicate()
                                break
                    if time.monotonic() - started > 120:
                        timed_out = True
                        process.terminate()
                        try:
                            stdout, stderr = process.communicate(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            stdout, stderr = process.communicate()
                        break
            elapsed = max(0.0, time.monotonic() - started)
            output = self.policies._redact(stdout or "", redactions=[settings.secret_key])  # noqa: SLF001
            err = self.policies._redact(stderr or "", redactions=[settings.secret_key])  # noqa: SLF001
            combined = output + ("\n" + err if err else "")
            if cancelled:
                return combined + "\nCommand interrupted: run cancelled.\n"
            if timed_out:
                return combined + f"\nCommand timed out after {elapsed:.1f}s.\n"
            if process.returncode != 0:
                return combined + f"\nCommand failed rc={process.returncode} after {elapsed:.1f}s.\n"
            return combined
        except OSError as exc:
            return f"Command failed (oserror): {exc}\n"

    def _parse_nmap(self, output: str) -> dict[str, list[str]]:
        ports = re.findall(r"(?m)^(\d{1,5})/tcp\s+open", output)
        services = re.findall(r"(?m)^\d{1,5}/tcp\s+open\s+([a-zA-Z0-9_.-]+)", output)
        return {"ports": sorted(set(ports)), "services": sorted(set(services))}
