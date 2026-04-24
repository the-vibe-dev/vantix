"""Tool protocol used by the executor agent.

A Tool is anything the executor can dispatch a ``ProposedAction`` to. The
contract is intentionally narrow so existing adapters (nmap, cve-search,
browser runtime, etc.) can be wrapped incrementally.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class ToolResult:
    status: str  # "completed" | "failed" | "blocked" | "skipped"
    summary: str = ""
    output_ref: str = ""
    artifact_ids: list[str] = field(default_factory=list)
    fact_ids: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Tool(Protocol):
    name: str

    def run(self, inputs: dict[str, Any]) -> ToolResult: ...
