from secops.agents.base import Agent, BaseAgent, RunState
from secops.agents.planner import PlannerAgent, StaticPlanner
from secops.bus.messages import Plan, ProposedAction


def test_base_agent_conforms_to_protocol():
    assert isinstance(BaseAgent(), Agent)


def test_static_planner_returns_fixed_actions():
    actions = [ProposedAction(action_type="nmap", objective="scan", target_ref="10.0.0.1")]
    planner = StaticPlanner(actions, rationale="recon first")
    state = RunState(run_id="r1", turn_id=3)
    plan = planner.plan(state)
    assert plan.turn_id == 3
    assert plan.rationale == "recon first"
    assert plan.actions == actions


def test_planner_agent_accepts_arbitrary_plan_fn():
    def fn(state: RunState) -> Plan:
        return Plan(
            turn_id=99,  # deliberately wrong to check normalization
            actions=[ProposedAction(action_type="http.get", objective="probe")],
        )

    planner = PlannerAgent(fn)
    plan = planner.plan(RunState(run_id="r1", turn_id=5))
    assert plan.turn_id == 5  # normalized to state.turn_id
    assert plan.actions[0].action_type == "http.get"
