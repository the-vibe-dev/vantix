from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from secops.services.vuln_intel import IntelRecord


@dataclass(frozen=True)
class SourceUpdateResult:
    source: str
    records: list[IntelRecord]
    cursor: dict[str, Any] = field(default_factory=dict)
    error: str = ""


class SourceAdapter(Protocol):
    name: str
    source_type: str
    url: str

    def fetch_since(self, cursor: dict[str, Any] | None = None) -> SourceUpdateResult:
        ...


def http_client(headers: dict[str, str] | None = None) -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=True, headers=headers or {})


def safe_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
