from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_planner_loop_test_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.agents.base import RunState
from secops.agents.evaluator import EvaluatorAgent
from secops.agents.executor import ExecutorAgent
from secops.agents.planner import PlannerAgent
from secops.bus.bus import AgentMessageBus
from secops.bus.messages import Plan, ProposedAction
from secops.db import Base, SessionLocal, engine
from secops.models import BusEvent, Engagement, WorkspaceRun
from secops.orchestration.planner_loop import LoopConfig, run_planner_loop
from secops.tools.base import ToolResult
from secops.tools.registry import ToolRegistry


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


class _EchoTool:
    name = "echo"

    def run(self, inputs):
        return ToolResult(status="completed", summary=f"echo:{inputs.get('msg','')}")


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="Loop Test", mode="pentest", target="x", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
    db.add(run)
    db.flush()
    return run


def test_single_turn_loop_publishes_plan_action_observation_critique():
    with SessionLocal() as db:
        run = _mk_run(db)
        run_id = run.id
        db.commit()

    reg = ToolRegistry()
    reg.register(_EchoTool())

    turns_seen = []

    def planner_fn(state: RunState) -> Plan:
        turns_seen.append(state.turn_id)
        if state.turn_id == 0:
            return Plan(
                turn_id=state.turn_id,
                actions=[ProposedAction(action_type="echo", objective="", inputs={"msg": "hi"})],
            )
        return Plan(turn_id=state.turn_id, actions=[])  # terminate

    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        result = run_planner_loop(
            bus=bus,
            run_id=run_id,
            planner=PlannerAgent(planner_fn),
            executor=ExecutorAgent(reg),
            evaluator=EvaluatorAgent(),
            build_state=lambda rid, turn, critique: RunState(run_id=rid, turn_id=turn, recent_critique=critique),
            config=LoopConfig(max_turns=3),
        )
        db.commit()

    assert result.turns_executed >= 1
    assert result.terminated_reason in {"no_replan", "empty_plan"}
    assert result.observations[0].status == "completed"

    with SessionLocal() as db:
        rows = db.query(BusEvent).filter(BusEvent.run_id == run_id).order_by(BusEvent.seq.asc()).all()
    types_by_turn: dict[int, list[str]] = {}
    for r in rows:
        types_by_turn.setdefault(r.turn_id, []).append(r.type)
    assert types_by_turn[0][:4] == ["plan", "action", "observation", "critique"]


def test_loop_terminates_on_empty_plan():
    with SessionLocal() as db:
        run = _mk_run(db)
        run_id = run.id
        db.commit()

    def empty(state: RunState) -> Plan:
        return Plan(turn_id=state.turn_id, actions=[])

    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        result = run_planner_loop(
            bus=bus,
            run_id=run_id,
            planner=PlannerAgent(empty),
            executor=ExecutorAgent(ToolRegistry()),
            evaluator=EvaluatorAgent(),
            build_state=lambda rid, turn, critique: RunState(run_id=rid, turn_id=turn),
            config=LoopConfig(max_turns=5),
        )
        db.commit()

    assert result.turns_executed == 1
    assert result.terminated_reason == "empty_plan"
    assert result.plans and not result.plans[0].actions
