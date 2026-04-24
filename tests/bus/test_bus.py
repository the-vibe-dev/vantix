from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_bus_test_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.bus import AgentMessageBus, BusCursor, BusEnvelope, Plan, ProposedAction
from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, WorkspaceRun


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="Bus Test", mode="pentest", target="127.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="127.0.0.1")
    db.add(run)
    db.flush()
    return run


def _plan_env(run_id: str, turn: int) -> BusEnvelope:
    plan = Plan(turn_id=turn, actions=[ProposedAction(action_type="nmap", objective="scan")])
    return BusEnvelope(
        run_id=run_id, turn_id=turn, agent="planner", type="plan", payload=plan.model_dump()
    )


def test_publish_assigns_monotonic_seq():
    with SessionLocal() as db:
        run = _mk_run(db)
        bus = AgentMessageBus(db)
        r1 = bus.publish(_plan_env(run.id, 0))
        r2 = bus.publish(_plan_env(run.id, 1))
        r3 = bus.publish(_plan_env(run.id, 2))
        db.commit()
        assert [r1.seq, r2.seq, r3.seq] == [1, 2, 3]


def test_branches_have_independent_seq():
    with SessionLocal() as db:
        run = _mk_run(db)
        bus = AgentMessageBus(db)
        bus.publish(_plan_env(run.id, 0))
        bus.publish(_plan_env(run.id, 1))
        branched = _plan_env(run.id, 0)
        branched = branched.model_copy(update={"branch_id": "fork-a"})
        r = bus.publish(branched)
        db.commit()
        assert r.branch_id == "fork-a"
        assert r.seq == 1  # independent from main


def test_read_respects_cursor():
    with SessionLocal() as db:
        run = _mk_run(db)
        run_id = run.id
        bus = AgentMessageBus(db)
        for i in range(5):
            bus.publish(_plan_env(run_id, i))
        db.commit()
    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        cursor = BusCursor()
        drained = list(bus.tail(run_id, cursor=cursor))
        assert len(drained) == 5
        assert cursor.last_seq == 5
        drained2 = list(bus.tail(run_id, cursor=cursor))
        assert drained2 == []


def test_envelopes_round_trip():
    with SessionLocal() as db:
        run = _mk_run(db)
        run_id = run.id
        bus = AgentMessageBus(db)
        bus.publish(_plan_env(run_id, 7))
        db.commit()
    with SessionLocal() as db:
        bus = AgentMessageBus(db)
        rows = bus.read(run_id)
        [env] = bus.envelopes(rows)
        assert env.turn_id == 7
        assert env.agent == "planner"
        assert Plan.model_validate(env.payload).actions[0].action_type == "nmap"
        assert env.content_hash  # auto-computed
