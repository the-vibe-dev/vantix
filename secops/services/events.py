from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secops.models import RunEvent


def normalize_event_payload(event_type: str, message: str, payload: dict | None = None) -> tuple[str, dict]:
    raw_type = str(event_type or "").strip()
    text = str(message or "").strip()
    data = dict(payload or {})
    if raw_type:
        data.setdefault("raw_event_type", raw_type)
    lower_message = text.lower()

    normalized = raw_type or "event"
    if raw_type == "phase":
        phase_name = str(data.get("phase") or data.get("origin_phase") or "")
        if phase_name:
            data.setdefault("phase_name", phase_name)
        if "report generated" in lower_message:
            normalized = "report_generated"
        elif phase_name == "browser-assessment" or str(data.get("source") or "").lower() == "browser-runtime":
            normalized = "browser_observation"
        else:
            normalized = "phase_transition"
    elif raw_type == "approval":
        if "granted" in lower_message or "approved" in lower_message:
            normalized = "approval_resolved"
            data.setdefault("resolution", "approved")
        elif "rejected" in lower_message or "denied" in lower_message:
            normalized = "approval_resolved"
            data.setdefault("resolution", "rejected")
        else:
            normalized = "approval_requested"
    elif raw_type == "finding":
        normalized = "finding_promoted"
    elif raw_type == "vector":
        normalized = "vector_generated"
    elif raw_type == "attack_chain":
        normalized = "attack_chain_generated"
    elif raw_type in {"agent_status", "policy_decision", "scheduler", "terminal", "run_status"}:
        normalized = raw_type

    return normalized, data


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
