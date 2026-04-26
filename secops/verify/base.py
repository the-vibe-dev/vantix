from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReplaySpec:
    """Normalized replay specification consumed by a ReplayVerifier.

    ``type`` selects the verifier (e.g. ``"http"``, ``"browser"``, ``"script"``,
    ``"artifact"``). Remaining fields are verifier-defined.
    """

    type: str
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_meta(cls, replay: dict[str, Any]) -> "ReplaySpec":
        kind = str(replay.get("type") or "").strip().lower()
        rest = {k: v for k, v in replay.items() if k != "type"}
        return cls(type=kind, payload=rest)


@dataclass
class VerifyContext:
    """Context handed to a verifier during dispatch.

    Attributes:
        run_id: Workspace run id (for event emission, audit).
        workspace_root: Optional path-like for artifact verifiers.
        extras: Verifier-specific overrides (timeouts, auth headers, etc.).
    """

    run_id: str | None = None
    workspace_root: Any = None
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerifyOutcome:
    validated: bool
    reason: str = ""
    proof_artifact_id: str | None = None
    reproduction_script: str = ""
    signal: dict[str, Any] = field(default_factory=dict)


class ReplayVerifier(ABC):
    """Abstract verifier. Implementations are registered with VerifierRegistry."""

    #: replay.type this verifier handles
    type: str = ""

    @abstractmethod
    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        ...
