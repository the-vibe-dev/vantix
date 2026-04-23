from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from secops.models import Artifact, RunEvent, WorkspaceRun
from secops.services.events import canonical_event_view


REPLAY_SCHEMA_VERSION = "vantix.replay.v1"


def build_replay_manifest(
    run: WorkspaceRun,
    events: Iterable[RunEvent],
    artifacts: Iterable[Artifact],
    *,
    phase_history: list[dict[str, Any]] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Build a stable replay manifest from immutable run evidence.

    This is intentionally derived from the current event/artifact stores rather
    than introducing a new persistence layer. It gives the UI/API a canonical
    reconstruction contract now, and leaves room for branch records later.
    """

    event_rows = list(events)
    artifact_rows = list(artifacts)
    canonical_events = [canonical_event_view(event) for event in event_rows]
    event_types: dict[str, int] = {}
    policy_verdicts: dict[str, int] = {}
    validation_statuses: dict[str, int] = {}
    artifact_kinds: dict[str, int] = {}

    for item in canonical_events:
        event_type = str(item.get("event_type") or "event")
        event_types[event_type] = event_types.get(event_type, 0) + 1
        policy = item.get("policy") if isinstance(item.get("policy"), dict) else {}
        verdict = str(policy.get("verdict") or "")
        if verdict:
            policy_verdicts[verdict] = policy_verdicts.get(verdict, 0) + 1
        validation = item.get("validation") if isinstance(item.get("validation"), dict) else {}
        status = str(validation.get("status") or "")
        if status:
            validation_statuses[status] = validation_statuses.get(status, 0) + 1

    for artifact in artifact_rows:
        kind = str(artifact.kind or "artifact")
        artifact_kinds[kind] = artifact_kinds.get(kind, 0) + 1

    first_sequence = int(canonical_events[0]["sequence"]) if canonical_events else 0
    last_sequence = int(canonical_events[-1]["sequence"]) if canonical_events else 0
    return {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "run_id": run.id,
        "base_run_id": run.resumed_from_run_id or None,
        "mode": "offline_reconstruct",
        "event_range": [first_sequence, last_sequence],
        "event_limit": limit,
        "phase_history_count": len(phase_history or []),
        "event_count": len(canonical_events),
        "event_types": event_types,
        "policy_verdicts": policy_verdicts,
        "validation_statuses": validation_statuses,
        "artifact_count": len(artifact_rows),
        "artifact_kinds": artifact_kinds,
        "config_snapshot": dict(run.config_json or {}),
    }

