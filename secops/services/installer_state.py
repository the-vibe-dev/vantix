from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secops.config import settings


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class InstallerStateService:
    def __init__(self, runtime_root: Path | None = None) -> None:
        self.runtime_root = (runtime_root or settings.runtime_root).resolve()
        self.install_root = self.runtime_root / "install"
        self.install_root.mkdir(parents=True, exist_ok=True)
        self.state_path = self.install_root / "installer_state.json"
        self.tool_history_path = self.install_root / "tool_install_history.jsonl"
        self.update_history_path = self.install_root / "update_history.jsonl"

    def read(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def write(self, payload: dict[str, Any]) -> dict[str, Any]:
        data = dict(payload)
        data.setdefault("updated_at", utc_ts())
        self.state_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return data

    def merge(self, payload: dict[str, Any]) -> dict[str, Any]:
        current = self.read()
        current.update(payload)
        return self.write(current)

    def append_tool_history(self, event: dict[str, Any]) -> dict[str, Any]:
        payload = dict(event)
        payload.setdefault("ts", utc_ts())
        with self.tool_history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
        return payload

    def tool_history(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self.tool_history_path.exists():
            return []
        rows = []
        for raw in self.tool_history_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw.strip():
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return rows[-limit:]

    def append_update_history(self, event: dict[str, Any]) -> dict[str, Any]:
        payload = dict(event)
        payload.setdefault("ts", utc_ts())
        with self.update_history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
        return payload

    def update_history(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.update_history_path.exists():
            return []
        rows = []
        for raw in self.update_history_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw.strip():
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return rows[-limit:]
