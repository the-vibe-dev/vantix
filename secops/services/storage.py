from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secops.config import settings


@dataclass(frozen=True)
class RunPaths:
    root: Path
    prompts: Path
    actions: Path
    artifacts: Path
    logs: Path
    handoffs: Path
    snapshots: Path
    notes: Path
    approvals: Path
    agents: Path
    facts: Path

    def ensure(self) -> "RunPaths":
        for path in (
            self.root,
            self.prompts,
            self.actions,
            self.artifacts,
            self.logs,
            self.handoffs,
            self.snapshots,
            self.notes,
            self.approvals,
            self.agents,
            self.facts,
        ):
            path.mkdir(parents=True, exist_ok=True)
        return self

    def write_text(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_json(self, path: Path, payload: dict[str, Any] | list[Any]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
        return path


class StorageLayout:
    """User-owned runtime storage for run artifacts and agent workspaces."""

    def __init__(self, runtime_root: Path | None = None) -> None:
        self.runtime_root = (runtime_root or settings.runtime_root).resolve()

    def for_workspace(self, workspace_id: str) -> RunPaths:
        root = self.runtime_root / "runs" / workspace_id
        return RunPaths(
            root=root,
            prompts=root / "prompts",
            actions=root / "actions",
            artifacts=root / "artifacts",
            logs=root / "logs",
            handoffs=root / "handoffs",
            snapshots=root / "snapshots",
            notes=root / "operator" / "notes",
            approvals=root / "operator" / "approvals",
            agents=root / "agents",
            facts=root / "facts",
        ).ensure()
