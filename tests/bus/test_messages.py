from secops.bus import (
    BusEnvelope,
    Critique,
    Observation,
    Plan,
    PolicyDecision,
    ProposedAction,
)


def test_proposed_action_round_trip():
    a = ProposedAction(
        action_type="http.get",
        objective="fetch admin panel",
        target_ref="https://example.com/admin",
        risk="medium",
        inputs={"method": "GET"},
        required_evidence=["http_exchange"],
        rationale="confirm auth boundary",
    )
    data = a.model_dump()
    assert ProposedAction.model_validate(data) == a


def test_plan_holds_actions():
    plan = Plan(
        turn_id=1,
        rationale="initial recon",
        actions=[
            ProposedAction(action_type="nmap.scan", objective="port sweep", target_ref="10.0.0.1"),
        ],
        budget_tokens=8000,
    )
    assert plan.actions[0].action_type == "nmap.scan"
    assert Plan.model_validate(plan.model_dump()) == plan


def test_observation_round_trip():
    o = Observation(
        action_id="act_1",
        action_type="nmap.scan",
        status="completed",
        summary="22,80 open",
        artifact_ids=["art_1"],
        metrics={"duration_ms": 1234},
    )
    assert Observation.model_validate(o.model_dump()) == o


def test_critique_defaults():
    c = Critique(turn_id=2, observations=["act_1", "act_2"])
    assert c.should_replan is True
    assert c.confidence == 0.0


def test_policy_decision_phases():
    for phase in ("capability", "plan_review", "action_gate"):
        d = PolicyDecision(phase=phase, verdict="allow", reason="")
        assert d.phase == phase


def test_envelope_kind_is_pinned():
    env = BusEnvelope(
        run_id="run_1",
        turn_id=0,
        agent="planner",
        type="plan",
        payload={"turn_id": 0, "actions": []},
    )
    assert env.schema_version == 2
    assert env.kind == "vantix.event.v2"
    assert env.branch_id == "main"
    dumped = env.model_dump()
    assert BusEnvelope.model_validate(dumped).ts == env.ts


def test_envelope_extra_forbidden():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        BusEnvelope(
            run_id="run_1",
            turn_id=0,
            agent="planner",
            type="plan",
            payload={},
            unexpected_field="nope",
        )
