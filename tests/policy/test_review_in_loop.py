from __future__ import annotations

import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_policy_loop_test_{os.getpid()}.db"
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
from secops.policy.review import review_plan as _review_plan
from secops.services.policies import ExecutionPolicyService
from secops.tools.registry import ToolRegistry


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="policy-loop", mode="pentest", target="x", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
    db.add(run)
    db.flush()
    return run


def test_blocked_plan_short_circuits_loop():
    with SessionLocal() as db:
        run = _mk_run(db)
        run_id, run_row = run.id, run
        db.commit()

    def planner_fn(state: RunState) -> Plan:
        return Plan(turn_id=state.turn_id, actions=[ProposedAction(action_type="script", objective="")])

    policies = ExecutionPolicyService()

    with patch("secops.services.policies.settings") as settings, SessionLocal() as db:
        settings.enable_script_execution = False
        settings.enable_codex_execution = True
        settings.enable_write_execution = True
        run_row = db.get(WorkspaceRun, run_id)
        bus = AgentMessageBus(db)
        result = run_planner_loop(
            bus=bus,
            run_id=run_id,
            planner=PlannerAgent(planner_fn),
            executor=ExecutorAgent(ToolRegistry()),
            evaluator=EvaluatorAgent(),
            build_state=lambda rid, turn, crit: RunState(run_id=rid, turn_id=turn),
            config=LoopConfig(max_turns=3),
            review_plan=lambda p: _review_plan(run_row, p, policies),
        )
        db.commit()

    assert result.turns_executed == 1
    assert result.terminated_reason == "plan_blocked"
    assert result.plan_reviews[0].verdict == "blocked"
    # no actions/observations were produced
    assert result.observations == []

    with SessionLocal() as db:
        types = [r.type for r in db.query(BusEvent).filter(BusEvent.run_id == run_id).order_by(BusEvent.seq.asc())]
    assert types == ["plan", "policy_decision"]
