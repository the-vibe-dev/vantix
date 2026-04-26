"""V25-05 — persistence layer for ReplaySpec.

Materializes a signed turn manifest (built by ``secops.replay.turn_manifest``)
into a ``ReplaySpec`` row so the replay engine has a stable handle to
target. Storing the canonical manifest JSON inline keeps replay
reproducible even if bus events are GC'd later.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from secops.models import ReplaySpec, WorkspaceRun
from secops.replay.turn_manifest import build_turn_manifest


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(manifest)).hexdigest()


@dataclass(frozen=True)
class ReplaySpecRecord:
    spec_id: str
    run_id: str
    branch_id: str
    manifest_sha256: str
    manifest: dict[str, Any]


def materialize(
    db: Session,
    run: WorkspaceRun,
    *,
    branch_id: str = "main",
    signed_by: str = "",
    signed_at: datetime | None = None,
) -> ReplaySpecRecord:
    """Build a turn manifest for ``(run, branch)`` and persist it as a ReplaySpec."""
    manifest = build_turn_manifest(db, run, branch_id=branch_id)
    sha = manifest_sha256(manifest)
    spec = ReplaySpec(
        run_id=run.id,
        branch_id=branch_id,
        manifest_sha256=sha,
        manifest_json=manifest,
        signed_at=signed_at,
        signed_by=signed_by,
    )
    db.add(spec)
    db.flush()
    return ReplaySpecRecord(
        spec_id=spec.id,
        run_id=run.id,
        branch_id=branch_id,
        manifest_sha256=sha,
        manifest=manifest,
    )


def load(db: Session, spec_id: str) -> ReplaySpecRecord:
    """Load a ReplaySpec row, returning its decoded manifest."""
    row = db.get(ReplaySpec, spec_id)
    if row is None:
        raise ValueError(f"replay spec not found: {spec_id}")
    return ReplaySpecRecord(
        spec_id=row.id,
        run_id=row.run_id,
        branch_id=row.branch_id,
        manifest_sha256=row.manifest_sha256,
        manifest=dict(row.manifest_json or {}),
    )


__all__ = ["ReplaySpecRecord", "manifest_sha256", "materialize", "load"]
