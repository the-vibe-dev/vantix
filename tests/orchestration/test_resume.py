"""V25-11/12 — RunTurnCheckpoint + pause / resume / auto-resume tests."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_resume_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.agents.base import RunState
from secops.agents.evaluator import EvaluatorAgent
from secops.agents.executor import ExecutorAgent
from secops.agents.planner import PlannerAgent
from secops.bus.bus import AgentMessageBus
from secops.bus.messages import Critique, Plan, ProposedAction
from secops.db import Base, SessionLocal, engine
from secops.models import BusEvent, ContentBlob, Engagement, RunTurnCheckpoint, WorkspaceRun
from secops.orchestration.planner_loop import LoopConfig, run_planner_loop
from secops.orchestration.resume import (
    auto_resume_running_runs,
    latest_checkpoint,
    pause,
    resume,
    write_checkpoint,
)
from secops.tools.registry import ToolRegistry


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _seed(db, status: str = "running") -> WorkspaceRun:
    eng = Engagement(name="r", mode="pentest", target="x", tags=["pentest"])
    db.add(eng); db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x", status=status)
    db.add(run); db.flush()
    return run


def test_write_checkpoint_persists_blob_and_row():
    with SessionLocal() as db:
        run = _seed(db); run_id = run.id
        snap = write_checkpoint(db, run_id=run_id, branch_id="main", turn_id=2, seq=8, state={"k": 1})
        db.commit()
    assert snap.run_state_blob_sha
    with SessionLocal() as db:
        assert db.query(RunTurnCheckpoint).filter_by(run_id=run_id).count() == 1
        assert db.query(ContentBlob).filter_by(sha256=snap.run_state_blob_sha).one().size_bytes > 0


def test_latest_checkpoint_picks_highest_turn():
    with SessionLocal() as db:
        run = _seed(db); run_id = run.id
        write_checkpoint(db, run_id=run_id, branch_id="main", turn_id=0, seq=1, state={})
        write_checkpoint(db, run_id=run_id, branch_id="main", turn_id=2, seq=8, state={})
        write_checkpoint(db, run_id=run_id, branch_id="main", turn_id=1, seq=4, state={})
        db.commit()
    with SessionLocal() as db:
        snap = latest_checkpoint(db, run_id)
    assert snap is not None
    assert snap.turn_id == 2 and snap.seq == 8


def test_planner_loop_writes_one_checkpoint_per_turn():
    with SessionLocal() as db:
        run = _seed(db); run_id = run.id; db.commit()

    def plan_fn(state: RunState) -> Plan:
        return Plan(turn_id=state.turn_id, actions=[ProposedAction(action_type="recon", objective=str(state.turn_id))])

    class Eval(EvaluatorAgent):
        def evaluate(self, observations):
            return Critique(turn_id=0, observations=[o.action_id for o in observations], should_replan=True)

    captured: list[dict] = []

    with SessionLocal() as db:
        bus = AgentMessageBus(db)

        def cp(run_id_, branch, turn, seq, plan, critique):
            write_checkpoint(db, run_id=run_id_, branch_id=branch, turn_id=turn, seq=seq,
                             state={"plan_actions": [a.action_type for a in plan.actions]})
            captured.append({"turn": turn})

        run_planner_loop(
            bus=bus, run_id=run_id, planner=PlannerAgent(plan_fn),
            executor=ExecutorAgent(ToolRegistry()), evaluator=Eval(),
            build_state=lambda r, t, c: RunState(run_id=r, turn_id=t),
            config=LoopConfig(max_turns=3, stop_when_no_replan=False),
            checkpoint=cp,
        )
        db.commit()

    assert len(captured) == 3
    with SessionLocal() as db:
        assert db.query(RunTurnCheckpoint).filter_by(run_id=run_id).count() == 3


def test_pause_then_resume_flips_status_and_returns_snapshot():
    with SessionLocal() as db:
        run = _seed(db, status="running"); run_id = run.id
        write_checkpoint(db, run_id=run_id, branch_id="main", turn_id=4, seq=12, state={"x": 1})
        db.commit()

    with SessionLocal() as db:
        pause(db, run_id, reason="op")
        db.commit()
        assert db.get(WorkspaceRun, run_id).status == "paused"

    with SessionLocal() as db:
        snap = resume(db, run_id)
        db.commit()
        assert db.get(WorkspaceRun, run_id).status == "resuming"
    assert snap is not None and snap.turn_id == 4 and snap.seq == 12

    # lifecycle events recorded
    with SessionLocal() as db:
        verdicts = [
            ev.payload_json.get("verdict")
            for ev in db.query(BusEvent).filter(BusEvent.run_id == run_id, BusEvent.type.in_(["run_paused", "run_resumed"]))
        ]
    assert "run_paused" in verdicts and "run_resumed" in verdicts


def test_auto_resume_resets_running_with_checkpoint():
    with SessionLocal() as db:
        a = _seed(db, status="running"); a_id = a.id
        b = _seed(db, status="running"); b_id = b.id
        c = _seed(db, status="completed"); c_id = c.id
        write_checkpoint(db, run_id=a_id, branch_id="main", turn_id=1, seq=3, state={})
        # b has no checkpoint
        write_checkpoint(db, run_id=c_id, branch_id="main", turn_id=0, seq=1, state={})
        db.commit()

    with SessionLocal() as db:
        reset = auto_resume_running_runs(db)
        db.commit()

    assert reset == [a_id]
    with SessionLocal() as db:
        assert db.get(WorkspaceRun, a_id).status == "resuming"
        assert db.get(WorkspaceRun, b_id).status == "running"
        assert db.get(WorkspaceRun, c_id).status == "completed"


def test_resume_without_checkpoint_returns_none_but_flips_status():
    with SessionLocal() as db:
        run = _seed(db, status="paused"); run_id = run.id; db.commit()
    with SessionLocal() as db:
        snap = resume(db, run_id); db.commit()
    assert snap is None
    with SessionLocal() as db:
        assert db.get(WorkspaceRun, run_id).status == "resuming"


def test_resume_rejects_terminal_states():
    with SessionLocal() as db:
        run = _seed(db, status="completed"); run_id = run.id; db.commit()
    with SessionLocal() as db:
        with pytest.raises(ValueError):
            resume(db, run_id)
