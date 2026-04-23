from __future__ import annotations

from datetime import datetime, timezone

from secops.telemetry.events import canonical_event_dict, canonicalize_payload


def test_canonicalize_payload_builds_event_envelope() -> None:
    event_type, payload = canonicalize_payload(
        event_type="approval",
        message="Approval granted: continue",
        payload={"reason": "recon_high_noise-policy"},
    )

    assert event_type == "approval_resolved"
    assert payload["schema_version"] == "vantix.event.v1"
    assert payload["canonical_event_type"] == "approval_resolved"
    assert payload["resolution"] == "approved"
    assert payload["risk"] == "info"


def test_canonical_event_dict_exposes_stable_replay_fields() -> None:
    view = canonical_event_dict(
        event_id="event-1",
        run_id="run-1",
        agent_session_id=None,
        sequence=1,
        event_type="policy_decision",
        level="info",
        message="policy:network:allow",
        payload={"action_kind": "network", "verdict": "allow", "reason": "in scope"},
        created_at=datetime.now(timezone.utc),
    )

    assert view["event_type"] == "policy_decision"
    assert view["schema_version"] == "vantix.event.v1"
    assert view["action_type"] == "network"
    assert view["policy"] == {"verdict": "allow", "reason": "in scope", "rule_ids": []}
