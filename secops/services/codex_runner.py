from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

from secops.config import settings


@dataclass
class CodexExecutionPlan:
    command: list[str]
    prompt: str
    workspace_dir: Path
    working_dir: Path

    @property
    def shell_preview(self) -> str:
        return " ".join(shlex.quote(part) for part in self.command)


class CodexRunner:
    def __init__(self, workspace_dir: Path) -> None:
        self.workspace_dir = workspace_dir
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

    def resolve_binary(self) -> str | None:
        configured = settings.codex_bin
        candidate = Path(configured)
        if candidate.is_file():
            return str(candidate)
        discovered = shutil.which(configured)
        if discovered:
            return discovered
        return None

    def is_available(self) -> bool:
        return self.resolve_binary() is not None

    def build_plan(self, prompt: str) -> CodexExecutionPlan:
        codex_bin = self.resolve_binary()
        if codex_bin is None:
            raise FileNotFoundError(f"Codex binary not found: {settings.codex_bin}")
        command = [
            codex_bin,
            "exec",
            "--model",
            settings.default_model,
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            "-C",
            str(settings.repo_root),
            prompt,
        ]
        return CodexExecutionPlan(
            command=command,
            prompt=prompt,
            workspace_dir=self.workspace_dir,
            working_dir=settings.repo_root,
        )

    def execute(self, plan: CodexExecutionPlan) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            plan.command,
            cwd=plan.working_dir,
            capture_output=True,
            text=True,
            check=False,
        )

    def execute_streaming(
        self,
        plan: CodexExecutionPlan,
        *,
        on_line,
        stop_event: threading.Event | None = None,
    ) -> subprocess.CompletedProcess[str]:
        process = subprocess.Popen(
            plan.command,
            cwd=plan.working_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        captured: list[str] = []
        assert process.stdout is not None
        for line in iter(process.stdout.readline, ""):
            if stop_event is not None and stop_event.is_set():
                process.kill()
                break
            captured.append(line)
            on_line(line)
        process.wait()
        return subprocess.CompletedProcess(plan.command, process.returncode, "".join(captured), "")
