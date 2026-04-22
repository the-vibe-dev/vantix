"""Phase-handler idempotency helpers.

Re-claimed phases (scavenger-recovered stale leases, handler-scheduled retries)
must not duplicate Facts on subsequent runs. The helpers here give handlers
two tools:

- ``phase_idempotency_key(run_id, phase_name, inputs)`` — stable hash used to
  stamp `WorkflowPhaseRun.metadata_json["idempotency_key"]` at claim time.
  Both retry paths (same-row scavenger re-claim, new-row schedule_retry)
  share the same key because it is keyed on ``(run_id, phase_name)``, not on
  the phase-run row id.

- ``upsert_fact_by_fingerprint(...)`` — UPSERT against ``Fact.fingerprint``
  (existing indexed column). If a matching fact already exists for the run,
  metadata is merged, confidence monotonically raised, tags unioned, and
  ``validated`` latched to True once ever observed. No new row is created.
  If nothing matches, a new Fact is inserted.

Handlers that write facts should prefer this helper when they can produce a
fingerprint; the existing ``secops.services.fingerprint.compute_fingerprint``
utility is the canonical way to generate one.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from sqlalchemy.orm import Session

from secops.models import Fact


def phase_idempotency_key(run_id: str, phase_name: str, inputs: dict[str, Any] | None = None) -> str:
    """Stable, deterministic key for a (run, phase, inputs) tuple.

    Truncated to 32 hex chars — collision space is enormous for per-run use.
    """
    material = {
        "run": str(run_id),
        "phase": str(phase_name),
        "inputs": inputs or {},
    }
    blob = json.dumps(material, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def upsert_fact_by_fingerprint(
    db: Session,
    *,
    run_id: str,
    fingerprint: str,
    kind: str,
    source: str = "",
    value: str = "",
    confidence: float = 0.0,
    tags: Iterable[str] | None = None,
    metadata: dict[str, Any] | None = None,
    validated: bool = False,
) -> tuple[Fact, bool]:
    """Insert or merge a Fact keyed by ``(run_id, fingerprint)``.

    Returns ``(fact, created)``. ``created=True`` means a new row was
    inserted; ``False`` means an existing row was merged.

    Merge rules (idempotent):
    - ``metadata_json`` is shallow-merged; new keys win.
    - ``confidence`` is raised but never lowered.
    - ``tags`` are unioned (sorted for determinism).
    - ``validated`` latches True once ever observed.
    - ``value``/``kind``/``source`` are not overwritten — first writer wins.
    """
    if not fingerprint:
        raise ValueError("fingerprint is required for upsert")

    existing = (
        db.query(Fact)
        .filter(Fact.run_id == run_id, Fact.fingerprint == fingerprint)
        .first()
    )
    if existing is not None:
        merged_meta = dict(existing.metadata_json or {})
        if metadata:
            merged_meta.update(metadata)
        existing.metadata_json = merged_meta
        if confidence and confidence > (existing.confidence or 0.0):
            existing.confidence = float(confidence)
        if validated and not existing.validated:
            existing.validated = True
        if tags:
            existing.tags = sorted(set(list(existing.tags or []) + list(tags)))
        db.flush()
        return existing, False

    fact = Fact(
        run_id=run_id,
        source=source,
        kind=kind,
        value=value,
        confidence=float(confidence),
        tags=sorted(set(tags or [])),
        metadata_json=dict(metadata or {}),
        validated=bool(validated),
        fingerprint=fingerprint,
    )
    db.add(fact)
    db.flush()
    return fact, True
