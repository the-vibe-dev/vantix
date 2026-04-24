"""V2-18 — YAML tool manifest loader.

Operators can add a Tool without touching Python by dropping a YAML
manifest into the tool-manifests directory::

    name: nmap_quick
    description: "Quick TCP SYN scan."
    kind: shell                   # only "shell" is supported today
    command: nmap                 # executable on $PATH
    args: ["-sS", "-T4", "{target}"]
    inputs:
      target: {required: true, type: string}
    timeout_seconds: 120

Placeholders in ``args`` are substituted from the ``inputs`` dict at
``Tool.run`` time; missing required inputs fail fast with a structured
``ToolResult(status=failed)``. No shell interpolation is performed
(``shell=False``), so string inputs cannot inject flags or commands.

This module is intentionally small and dependency-light: pyyaml is an
optional extra on the SDK; when the loader is used from secops it is
already available.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from secops.tools.base import Tool, ToolResult
from secops.tools.registry import ToolRegistry


SUPPORTED_KINDS = {"shell"}


class ManifestError(ValueError):
    """Raised when a YAML tool manifest is malformed."""


@dataclass
class ToolManifest:
    name: str
    description: str
    kind: str
    command: str
    args: list[str]
    inputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    timeout_seconds: float | None = None

    @classmethod
    def from_mapping(cls, data: dict[str, Any], *, source: str = "<inline>") -> "ToolManifest":
        try:
            name = str(data["name"]).strip()
            kind = str(data.get("kind", "shell")).strip().lower()
            command = str(data["command"]).strip()
        except KeyError as exc:
            raise ManifestError(f"{source}: missing required field {exc.args[0]!r}") from exc
        if not name:
            raise ManifestError(f"{source}: name must not be empty")
        if kind not in SUPPORTED_KINDS:
            raise ManifestError(f"{source}: unsupported kind {kind!r}; supported: {sorted(SUPPORTED_KINDS)}")
        if not command:
            raise ManifestError(f"{source}: command must not be empty")
        args_raw = data.get("args", [])
        if not isinstance(args_raw, list):
            raise ManifestError(f"{source}: args must be a list of strings")
        args = [str(a) for a in args_raw]
        inputs_raw = data.get("inputs", {}) or {}
        if not isinstance(inputs_raw, dict):
            raise ManifestError(f"{source}: inputs must be a mapping")
        inputs: dict[str, dict[str, Any]] = {}
        for key, spec in inputs_raw.items():
            if not isinstance(spec, dict):
                raise ManifestError(f"{source}: inputs.{key} must be a mapping")
            inputs[str(key)] = dict(spec)
        timeout_raw = data.get("timeout_seconds")
        timeout = float(timeout_raw) if timeout_raw is not None else None
        return cls(
            name=name,
            description=str(data.get("description", "") or ""),
            kind=kind,
            command=command,
            args=args,
            inputs=inputs,
            timeout_seconds=timeout,
        )

    @classmethod
    def from_yaml(cls, path: Path) -> "ToolManifest":
        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ManifestError(f"{path}: root must be a mapping")
        return cls.from_mapping(data, source=str(path))


class ShellTool:
    """A :class:`secops.tools.base.Tool` backed by an external executable.

    Constructed from a :class:`ToolManifest`; safe to register with a
    :class:`ToolRegistry`. ``subprocess.run`` is invoked with ``shell=False``
    so input substitution cannot escape into the shell.
    """

    def __init__(self, manifest: ToolManifest, *, executor=subprocess.run):
        self.manifest = manifest
        self._executor = executor

    @property
    def name(self) -> str:
        return self.manifest.name

    def run(self, inputs: dict[str, Any]) -> ToolResult:
        try:
            resolved_args = self._resolve_args(inputs)
        except ManifestError as exc:
            return ToolResult(status="failed", summary=str(exc), error={"reason": "bad_inputs", "detail": str(exc)})
        binary = shutil.which(self.manifest.command) or self.manifest.command
        argv = [binary, *resolved_args]
        try:
            proc = self._executor(
                argv,
                capture_output=True,
                text=True,
                timeout=self.manifest.timeout_seconds,
                check=False,
                shell=False,
            )
        except FileNotFoundError as exc:
            return ToolResult(status="failed", summary=f"binary not found: {self.manifest.command}",
                              error={"reason": "binary_not_found", "detail": str(exc)})
        except subprocess.TimeoutExpired as exc:
            return ToolResult(status="failed", summary=f"timeout after {self.manifest.timeout_seconds}s",
                              error={"reason": "timeout", "detail": str(exc)})
        status = "completed" if proc.returncode == 0 else "failed"
        return ToolResult(
            status=status,
            summary=(proc.stdout or "").strip()[:500],
            metrics={"exit_code": int(proc.returncode), "stdout_len": len(proc.stdout or ""),
                     "stderr_len": len(proc.stderr or "")},
            error={} if status == "completed" else {"reason": "nonzero_exit", "stderr": (proc.stderr or "")[:500]},
        )

    def _resolve_args(self, inputs: dict[str, Any]) -> list[str]:
        # Validate required inputs first so missing ones fail fast.
        for key, spec in self.manifest.inputs.items():
            if spec.get("required") and key not in inputs:
                raise ManifestError(f"missing required input: {key}")
        resolved: list[str] = []
        for template in self.manifest.args:
            try:
                resolved.append(template.format(**inputs))
            except KeyError as exc:
                raise ManifestError(f"unresolved placeholder in arg {template!r}: {exc.args[0]!r}") from exc
        return resolved


def load_manifest_dir(path: Path, registry: ToolRegistry) -> list[ToolManifest]:
    """Discover ``*.yaml`` / ``*.yml`` manifests under ``path`` and register them."""
    base = Path(path)
    if not base.is_dir():
        raise ManifestError(f"tool manifest dir not found: {base}")
    loaded: list[ToolManifest] = []
    for file in sorted(list(base.glob("*.yaml")) + list(base.glob("*.yml"))):
        manifest = ToolManifest.from_yaml(file)
        registry.register(ShellTool(manifest))
        loaded.append(manifest)
    return loaded


__all__ = [
    "ManifestError",
    "ShellTool",
    "ToolManifest",
    "load_manifest_dir",
]
