from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secops.adapters.script_catalog import SCRIPT_CATALOG, ScriptDefinition
from secops.config import settings


@dataclass
class ScriptExecutionResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


class ScriptAdapter:
    def __init__(self, mode: str) -> None:
        self.mode = mode

    def get(self, script_id: str) -> ScriptDefinition:
        definition = SCRIPT_CATALOG[script_id]
        if self.mode not in definition.modes:
            raise PermissionError(f"{script_id} is not available in mode {self.mode}")
        return definition

    def preview(self, script_id: str, *args: str) -> dict[str, Any]:
        definition = self.get(script_id)
        command = ["bash", str(definition.resolved_path()), *args]
        return {
            "script": definition.to_dict(),
            "command": command,
            "shell_preview": " ".join(shlex.quote(part) for part in command),
        }

    def execute(self, script_id: str, *args: str, cwd: Path | None = None) -> ScriptExecutionResult:
        if not settings.enable_script_execution:
            raise RuntimeError("Execution is disabled. Set SECOPS_ENABLE_SCRIPT_EXECUTION=true to enable.")
        preview = self.preview(script_id, *args)
        result = subprocess.run(
            preview["command"],
            cwd=cwd or settings.repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        return ScriptExecutionResult(
            command=preview["command"],
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
