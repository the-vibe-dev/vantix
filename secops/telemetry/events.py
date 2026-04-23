from __future__ import annotations

from typing import Any


EVENT_SCHEMA_VERSION = "vantix.event.v1"


def normalize_event_type(event_type: str, message: str, payload: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
    """Normalize legacy event names into the canonical stream vocabulary."""

    raw_type = str(event_type or "").strip()
    text = str(message or "").strip()
    data = dict(payload or {})
    if raw_type:
        data.setdefault("raw_event_type", raw_type)

    explicit = str(data.get("canonical_event_type") or data.get("event_type_canonical") or "").strip()
    if explicit:
        return explicit, data

    lower_message = text.lower()
    normalized = raw_type or "event"
    if raw_type == "phase":
        phase_name = str(data.get("phase") or data.get("phase_name") or data.get("origin_phase") or "")
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
    elif raw_type in {
        "agent_status",
        "approval_requested",
        "approval_resolved",
        "attack_chain_generated",
        "browser_observation",
        "dedup_merged",
        "finding_promoted",
        "finding_reviewed",
        "finding_suppressed",
        "memory_error",
        "policy_decision",
        "report_generated",
        "run_status",
        "scheduler",
        "skills",
        "terminal",
        "vector_generated",
        "vector_refuted",
        "vector_validated",
    }:
        normalized = raw_type
    return normalized, data


def canonicalize_payload(
    *,
    event_type: str,
    message: str,
    payload: dict[str, Any] | None = None,
    agent_session_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return canonical event type plus a replay-safe payload envelope.

    Existing payload keys are preserved. Stable fields are added only when
    absent so older callers keep working while new callers gain a dependable
    contract.
    """

    canonical_type, data = normalize_event_type(event_type, message, payload)
    data.setdefault("schema_version", EVENT_SCHEMA_VERSION)
    data.setdefault("canonical_event_type", canonical_type)
    data.setdefault("parent_event_id", data.get("parent_event_id"))
    data.setdefault("phase", data.get("phase_name") or data.get("phase") or data.get("origin_phase") or "")
    data.setdefault("agent_role", data.get("agent_role") or data.get("agent") or "")
    data.setdefault("target_ref", data.get("target_ref") or data.get("target") or data.get("url") or "")
    data.setdefault("risk", data.get("risk") or data.get("severity") or "info")
    data.setdefault("artifact_ids", _coerce_list(data.get("artifact_ids") or data.get("evidence_artifact_ids") or data.get("artifact_id")))
    data.setdefault("graph_delta_ids", _coerce_list(data.get("graph_delta_ids") or data.get("graph_delta_id")))
    data.setdefault("action", _action_from_payload(canonical_type, data))
    data.setdefault("policy", _policy_from_payload(canonical_type, data))
    data.setdefault("validation", _validation_from_payload(canonical_type, data))
    data.setdefault("metrics", data.get("metrics") if isinstance(data.get("metrics"), dict) else {})
    data.setdefault("error", _error_from_payload(canonical_type, data, message))
    if agent_session_id:
        data.setdefault("agent_session_id", agent_session_id)
    return canonical_type, data


def canonical_event_dict(
    *,
    event_id: str,
    run_id: str,
    agent_session_id: str | None,
    sequence: int,
    event_type: str,
    level: str,
    message: str,
    payload: dict[str, Any] | None,
    created_at: Any,
) -> dict[str, Any]:
    canonical_type, data = canonicalize_payload(
        event_type=event_type,
        message=message,
        payload=payload,
        agent_session_id=agent_session_id,
    )
    return {
        "id": event_id,
        "run_id": run_id,
        "agent_session_id": agent_session_id,
        "sequence": sequence,
        "event_type": canonical_type,
        "level": level,
        "message": message,
        "payload_json": data,
        "created_at": created_at,
        "schema_version": data.get("schema_version", EVENT_SCHEMA_VERSION),
        "parent_event_id": data.get("parent_event_id"),
        "phase": data.get("phase") or "",
        "agent_role": data.get("agent_role") or "",
        "target_ref": data.get("target_ref") or "",
        "action_id": (data.get("action") or {}).get("id") if isinstance(data.get("action"), dict) else "",
        "action_type": (data.get("action") or {}).get("type") if isinstance(data.get("action"), dict) else "",
        "risk": data.get("risk") or "info",
        "policy": data.get("policy") if isinstance(data.get("policy"), dict) else {},
        "validation": data.get("validation") if isinstance(data.get("validation"), dict) else {},
        "metrics": data.get("metrics") if isinstance(data.get("metrics"), dict) else {},
        "error": data.get("error") if isinstance(data.get("error"), dict) else {},
        "artifact_ids": _coerce_list(data.get("artifact_ids")),
        "graph_delta_ids": _coerce_list(data.get("graph_delta_ids")),
    }


def _coerce_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, tuple | set):
        return [str(item) for item in value if str(item)]
    return [str(value)]


def _action_from_payload(canonical_type: str, data: dict[str, Any]) -> dict[str, Any]:
    existing = data.get("action")
    if isinstance(existing, dict):
        return existing
    action_type = str(data.get("action_type") or data.get("action_kind") or "")
    if not action_type and canonical_type in {"policy_decision", "terminal"}:
        action_type = str(data.get("tool") or data.get("command") or canonical_type)
    return {
        "id": str(data.get("action_id") or ""),
        "type": action_type,
        "status": str(data.get("action_status") or ""),
        "input_ref": str(data.get("input_ref") or ""),
        "output_ref": str(data.get("output_ref") or ""),
    }


def _policy_from_payload(canonical_type: str, data: dict[str, Any]) -> dict[str, Any]:
    existing = data.get("policy")
    if isinstance(existing, dict):
        return existing
    if canonical_type != "policy_decision" and "verdict" not in data and "reason" not in data:
        return {}
    return {
        "verdict": str(data.get("verdict") or data.get("decision") or ""),
        "reason": str(data.get("reason") or ""),
        "rule_ids": _coerce_list(data.get("rule_ids") or data.get("rule_id")),
    }


def _validation_from_payload(canonical_type: str, data: dict[str, Any]) -> dict[str, Any]:
    existing = data.get("validation")
    if isinstance(existing, dict):
        return existing
    if canonical_type == "vector_validated":
        status = "validated"
    elif canonical_type == "vector_refuted":
        status = "rejected"
    elif canonical_type == "finding_promoted":
        status = "validated"
    else:
        status = str(data.get("validation_status") or "")
    if not status:
        return {}
    return {
        "status": status,
        "finding_id": str(data.get("finding_id") or ""),
        "source_id": str(data.get("source_id") or data.get("fact_id") or ""),
        "reason": str(data.get("validation_reason") or data.get("reason") or ""),
    }


def _error_from_payload(canonical_type: str, data: dict[str, Any], message: str) -> dict[str, Any]:
    existing = data.get("error")
    if isinstance(existing, dict):
        return existing
    level = str(data.get("level") or "").lower()
    if canonical_type not in {"memory_error"} and level != "error" and "failed" not in message.lower():
        return {}
    return {
        "class": str(data.get("error_class") or "runtime"),
        "message": str(data.get("error_message") or message or ""),
    }

