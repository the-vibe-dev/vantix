"""V25-08/09 — extended Decision verdicts in the planner loop."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_decision_verdicts_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.agents.base import RunState
from secops.agents.evaluator import EvaluatorAgent
from secops.agents.executor import ExecutorAgent
from secops.agents.planner import PlannerAgent
from secops.bus.bus import AgentMessageBus
from secops.bus.messages import Critique, Plan, ProposedAction
from secops.db import Base, SessionLocal, engine
from secops.models import BusEvent, Engagement, WorkspaceRun
from secops.orchestration.planner_loop import LoopConfig, run_planner_loop
from secops.policy.decision import Decision, SandboxConstraints
from secops.tools.registry import ToolRegistry


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _seed(db) -> WorkspaceRun:
    eng = Engagement(name="dv", mode="pentest", target="x", tags=["pentest"])
    db.add(eng); db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
    db.add(run); db.flush()
    return run


def _planner_calls() -> tuple[PlannerAgent, dict]:
    calls = {"n": 0}
    def plan_fn(state: RunState) -> Plan:
        calls["n"] += 1
        return Plan(
            turn_id=state.turn_id,
            actions=[ProposedAction(action_type="recon", objective="probe", risk="low")],
        )
    return PlannerAgent(plan_fn), calls


class _StubEvaluator(EvaluatorAgent):
    def evaluate(self, observations):
        return Critique(turn_id=0, observations=[o.action_id for o in observations], should_replan=False)


def test_rewrite_plan_replaces_plan_without_re_invoking_planner():
    with SessionLocal() as db:
        run = _seed(db); run_id = run.id; db.commit()

    planner, calls = _planner_calls()
    rewritten = Plan(
        turn_id=0,
        rationale="safer",
        actions=[ProposedAction(action_type="report", objective="stop", risk="info")],
    )

    def decide(plan):
        if any(a.action_type == "report" for a in plan.actions):
            return Decision(verdict="allow", reason="post-rewrite")
        return Decision(verdict="rewrite_plan", reason="too risky", rewrite=rewritten)

    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        result = run_planner_loop(
            bus=bus, run_id=run_id, planner=planner,
            executor=ExecutorAgent(ToolRegistry()), evaluator=_StubEvaluator(),
            build_state=lambda r, t, c: RunState(run_id=r, turn_id=t),
            config=LoopConfig(max_turns=1),
            decide_plan=decide,
        )
        db.commit()

    assert calls["n"] == 1, "planner.plan must not be re-invoked on rewrite_plan"
    assert result.plans[-1].actions[0].action_type == "report"
    assert any(d.verdict == "rewrite_plan" for d in result.decisions)
    with SessionLocal() as db:
        actions = [r for r in db.query(BusEvent).filter(BusEvent.run_id == run_id, BusEvent.type == "action_dispatched")]
    assert actions and actions[0].payload_json["action_type"] == "report"


def test_double_rewrite_is_hard_block():
    with SessionLocal() as db:
        run = _seed(db); run_id = run.id; db.commit()

    planner, calls = _planner_calls()
    rewrite_a = Plan(turn_id=0, actions=[ProposedAction(action_type="recon", objective="A")])
    rewrite_b = Plan(turn_id=0, actions=[ProposedAction(action_type="recon", objective="B")])

    seq = iter([
        Decision(verdict="rewrite_plan", reason="r1", rewrite=rewrite_a),
        Decision(verdict="rewrite_plan", reason="r2", rewrite=rewrite_b),
    ])
    def decide(_plan):
        return next(seq)

    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        result = run_planner_loop(
            bus=bus, run_id=run_id, planner=planner,
            executor=ExecutorAgent(ToolRegistry()), evaluator=_StubEvaluator(),
            build_state=lambda r, t, c: RunState(run_id=r, turn_id=t),
            config=LoopConfig(max_turns=2),
            decide_plan=decide,
        )
        db.commit()

    assert result.terminated_reason == "plan_rewrite_loop"
    assert calls["n"] == 1
    with SessionLocal() as db:
        actions = list(db.query(BusEvent).filter(BusEvent.run_id == run_id, BusEvent.type == "action_dispatched"))
    assert actions == [], "blocked rewrite-loop must not dispatch any action"


def test_downgrade_action_patches_action_in_place():
    with SessionLocal() as db:
        run = _seed(db); run_id = run.id; db.commit()

    planner, calls = _planner_calls()
    safer = ProposedAction(action_type="recon", objective="safe-probe", risk="info")

    def decide(_plan):
        return Decision(verdict="downgrade_action", reason="risk", downgrade={0: safer})

    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        result = run_planner_loop(
            bus=bus, run_id=run_id, planner=planner,
            executor=ExecutorAgent(ToolRegistry()), evaluator=_StubEvaluator(),
            build_state=lambda r, t, c: RunState(run_id=r, turn_id=t),
            config=LoopConfig(max_turns=1),
            decide_plan=decide,
        )
        db.commit()

    assert calls["n"] == 1
    assert result.plans[-1].actions[0].objective == "safe-probe"
    with SessionLocal() as db:
        action_ev = next(iter(db.query(BusEvent).filter(BusEvent.run_id == run_id, BusEvent.type == "action_dispatched")))
    assert action_ev.payload_json["objective"] == "safe-probe"


def test_route_to_verifier_annotates_action_payload():
    with SessionLocal() as db:
        run = _seed(db); run_id = run.id; db.commit()

    planner, _ = _planner_calls()
    def decide(_plan):
        return Decision(verdict="route_to_verifier", verifier_id="browser", reason="needs DOM")

    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        run_planner_loop(
            bus=bus, run_id=run_id, planner=planner,
            executor=ExecutorAgent(ToolRegistry()), evaluator=_StubEvaluator(),
            build_state=lambda r, t, c: RunState(run_id=r, turn_id=t),
            config=LoopConfig(max_turns=1),
            decide_plan=decide,
        )
        db.commit()
    with SessionLocal() as db:
        action_ev = next(iter(db.query(BusEvent).filter(BusEvent.run_id == run_id, BusEvent.type == "action_dispatched")))
    assert action_ev.payload_json["policy"]["verifier_id"] == "browser"


def test_sandbox_only_attaches_constraints():
    with SessionLocal() as db:
        run = _seed(db); run_id = run.id; db.commit()

    planner, _ = _planner_calls()
    def decide(_plan):
        return Decision(
            verdict="sandbox_only",
            sandbox=SandboxConstraints(network=False, max_runtime_seconds=30),
        )

    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        run_planner_loop(
            bus=bus, run_id=run_id, planner=planner,
            executor=ExecutorAgent(ToolRegistry()), evaluator=_StubEvaluator(),
            build_state=lambda r, t, c: RunState(run_id=r, turn_id=t),
            config=LoopConfig(max_turns=1),
            decide_plan=decide,
        )
        db.commit()
    with SessionLocal() as db:
        action_ev = next(iter(db.query(BusEvent).filter(BusEvent.run_id == run_id, BusEvent.type == "action_dispatched")))
    sandbox = action_ev.payload_json["policy"]["sandbox"]
    assert sandbox["network"] is False
    assert sandbox["max_runtime_seconds"] == 30


def test_block_terminates_loop():
    with SessionLocal() as db:
        run = _seed(db); run_id = run.id; db.commit()

    planner, _ = _planner_calls()
    def decide(_plan):
        return Decision(verdict="block", reason="hard no")

    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        result = run_planner_loop(
            bus=bus, run_id=run_id, planner=planner,
            executor=ExecutorAgent(ToolRegistry()), evaluator=_StubEvaluator(),
            build_state=lambda r, t, c: RunState(run_id=r, turn_id=t),
            config=LoopConfig(max_turns=2),
            decide_plan=decide,
        )
        db.commit()
    assert result.terminated_reason == "plan_block"
    with SessionLocal() as db:
        types = [r.type for r in db.query(BusEvent).filter(BusEvent.run_id == run_id).order_by(BusEvent.seq.asc())]
    assert "action" not in types


def test_decision_apply_unchanged_for_allow():
    plan = Plan(turn_id=3, actions=[ProposedAction(action_type="recon", objective="x")])
    d = Decision(verdict="allow")
    assert d.apply(plan) is plan


def test_decision_apply_rewrite_preserves_turn_id():
    plan = Plan(turn_id=7, actions=[ProposedAction(action_type="recon", objective="x")])
    rewrite = Plan(turn_id=0, actions=[ProposedAction(action_type="report", objective="r")])
    d = Decision(verdict="rewrite_plan", rewrite=rewrite)
    out = d.apply(plan)
    assert out.turn_id == 7
    assert out.actions[0].action_type == "report"
