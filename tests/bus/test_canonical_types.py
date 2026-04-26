"""V25-13 — canonical BusEvent.type Literal + legacy coercion."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from secops.bus.messages import LEGACY_TYPE_MAP, BusEnvelope, canonicalize_type


CANONICAL_TYPES = [
    "plan_proposed",
    "plan_revised",
    "plan_blocked",
    "action_dispatched",
    "observation_recorded",
    "policy_evaluated",
    "proof_created",
    "fact_promoted",
    "turn_committed",
    "run_paused",
    "run_resumed",
    "run_branched",
]


@pytest.mark.parametrize("ev_type", CANONICAL_TYPES)
def test_canonical_type_round_trips(ev_type):
    env = BusEnvelope(run_id="r", turn_id=0, agent="planner", type=ev_type, payload={})
    assert env.type == ev_type
    assert BusEnvelope.model_validate(env.model_dump()).type == ev_type


@pytest.mark.parametrize("legacy,canonical", list(LEGACY_TYPE_MAP.items()))
def test_legacy_type_coerced_to_canonical(legacy, canonical):
    env = BusEnvelope(run_id="r", turn_id=0, agent="planner", type=legacy, payload={})
    assert env.type == canonical


def test_unknown_type_rejected():
    with pytest.raises(ValidationError):
        BusEnvelope(run_id="r", turn_id=0, agent="planner", type="bogus_event", payload={})


def test_canonicalize_type_helper_is_idempotent():
    for canonical in CANONICAL_TYPES:
        assert canonicalize_type(canonical) == canonical
    for legacy, canonical in LEGACY_TYPE_MAP.items():
        assert canonicalize_type(legacy) == canonical
