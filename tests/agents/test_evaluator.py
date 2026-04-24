from secops.agents.evaluator import EvaluatorAgent
from secops.bus.messages import Observation


def _obs(status: str, aid: str = "a") -> Observation:
    return Observation(action_id=aid, action_type="nmap", status=status, summary=f"{aid}:{status}")


def test_empty_observations_no_replan():
    c = EvaluatorAgent().evaluate([])
    assert c.should_replan is False
    assert c.confidence == 0.0


def test_all_completed_no_replan():
    c = EvaluatorAgent().evaluate([_obs("completed", "a1"), _obs("completed", "a2")])
    assert c.confidence == 1.0
    assert c.should_replan is False
    assert set(c.observations) == {"a1", "a2"}


def test_replan_on_failure_flag_suppresses_failure_driven_replan():
    c = EvaluatorAgent(replan_on_failure=False).evaluate(
        [_obs("completed", "a1"), _obs("failed", "a2")]
    )
    # confidence < 1.0 still forces a replan (incomplete work),
    # but the failure-specific trigger is suppressed.
    assert c.should_replan is True
    assert c.confidence == 0.5


def test_any_failure_triggers_replan():
    c = EvaluatorAgent().evaluate([_obs("completed", "a1"), _obs("failed", "a2")])
    assert c.should_replan is True
    assert 0 < c.confidence < 1.0
