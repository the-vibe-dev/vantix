from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secops.models import RunEvent
from secops.telemetry.events import canonical_event_dict, canonicalize_payload, normalize_event_type


def normalize_event_payload(event_type: str, message: str, payload: dict | None = None) -> tuple[str, dict]:
    return normalize_event_type(event_type, message, payload)


def canonical_event_view(event: RunEvent) -> dict:
    return canonical_event_dict(
        event_id=event.id,
        run_id=event.run_id,
        agent_session_id=event.agent_session_id,
        sequence=event.sequence,
        event_type=event.event_type,
        level=event.level,
        message=event.message,
        payload=event.payload_json,
        created_at=event.created_at,
    )


class RunEventService:
    def emit(
        self,
        db: Session,
        run_id: str,
        event_type: str,
        message: str,
        *,
        level: str = "info",
        payload: dict | None = None,
        agent_session_id: str | None = None,
    ) -> RunEvent:
        current = db.execute(select(func.max(RunEvent.sequence)).where(RunEvent.run_id == run_id)).scalar() or 0
        canonical_type, canonical_payload = canonicalize_payload(
            event_type=event_type,
            message=message,
            payload=payload,
            agent_session_id=agent_session_id,
        )
        event = RunEvent(
            run_id=run_id,
            agent_session_id=agent_session_id,
            sequence=current + 1,
            event_type=canonical_type,
            level=level,
            message=message,
            payload_json=canonical_payload,
        )
        db.add(event)
        db.flush()
        return event
