from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secops.models import RunEvent


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
        event = RunEvent(
            run_id=run_id,
            agent_session_id=agent_session_id,
            sequence=current + 1,
            event_type=event_type,
            level=level,
            message=message,
            payload_json=payload or {},
        )
        db.add(event)
        db.flush()
        return event
