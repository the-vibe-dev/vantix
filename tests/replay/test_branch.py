"""V2-13 — branch_from_step primitive."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_branch_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope
from secops.db import Base, SessionLocal, engine
from secops.models import BusEvent, Engagement, WorkspaceRun
from secops.replay.branch import branch_from_step


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _seed_run(db) -> WorkspaceRun:
    eng = Engagement(name="br", mode="pentest", target="x", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
    db.add(run)
    db.flush()
    return run


def _seed_turns(bus: AgentMessageBus, run_id: str) -> None:
    bus.publish(BusEnvelope(run_id=run_id, turn_id=0, agent="planner", type="plan", payload={"t": 0}))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=0, agent="executor", type="action", payload={"t": 0}))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=1, agent="planner", type="plan", payload={"t": 1}))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=1, agent="executor", type="action", payload={"t": 1}))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=2, agent="planner", type="plan", payload={"t": 2}))


def test_fork_copies_events_up_to_turn_inclusive():
    with SessionLocal() as db:
        run = _seed_run(db)
        run_id = run.id
        _seed_turns(AgentMessageBus(db), run_id)
        db.commit()
        res = branch_from_step(db, run_id=run_id, fork_turn_id=1, new_branch_id="fork")
        db.commit()
    assert res.copied_count == 4
    assert res.new_branch_id == "fork"
    with SessionLocal() as db:
        fork_rows = (
            db.query(BusEvent)
            .filter(BusEvent.run_id == run_id, BusEvent.branch_id == "fork")
            .order_by(BusEvent.seq.asc())
            .all()
        )
    assert [r.turn_id for r in fork_rows] == [0, 0, 1, 1]
    assert [r.seq for r in fork_rows] == [1, 2, 3, 4]  # fresh seq on the branch
    # parent_turn_id was absent on originals → set to fork_turn_id
    assert all(r.parent_turn_id == 1 for r in fork_rows)


def test_fork_with_later_turn_excluded():
    with SessionLocal() as db:
        run = _seed_run(db)
        run_id = run.id
        _seed_turns(AgentMessageBus(db), run_id)
        db.commit()
        branch_from_step(db, run_id=run_id, fork_turn_id=0, new_branch_id="early")
        db.commit()
    with SessionLocal() as db:
        rows = (
            db.query(BusEvent)
            .filter(BusEvent.run_id == run_id, BusEvent.branch_id == "early")
            .all()
        )
    assert len(rows) == 2
    assert all(r.turn_id == 0 for r in rows)


def test_fork_then_diverge_does_not_affect_main():
    with SessionLocal() as db:
        run = _seed_run(db)
        run_id = run.id
        _seed_turns(AgentMessageBus(db), run_id)
        db.commit()
        branch_from_step(db, run_id=run_id, fork_turn_id=1, new_branch_id="alt")
        # Diverge: publish a new action on the fork at turn 2
        AgentMessageBus(db).publish(
            BusEnvelope(run_id=run_id, branch_id="alt", turn_id=2, agent="planner", type="plan", payload={"diverged": True})
        )
        db.commit()
    with SessionLocal() as db:
        main_count = db.query(BusEvent).filter(BusEvent.run_id == run_id, BusEvent.branch_id == "main").count()
        alt_count = db.query(BusEvent).filter(BusEvent.run_id == run_id, BusEvent.branch_id == "alt").count()
    assert main_count == 5
    assert alt_count == 5  # 4 copied + 1 divergent


def test_fork_rejects_existing_branch():
    with SessionLocal() as db:
        run = _seed_run(db)
        run_id = run.id
        _seed_turns(AgentMessageBus(db), run_id)
        db.commit()
        branch_from_step(db, run_id=run_id, fork_turn_id=0, new_branch_id="dup")
        db.commit()
        with pytest.raises(ValueError, match="already has events"):
            branch_from_step(db, run_id=run_id, fork_turn_id=0, new_branch_id="dup")


def test_fork_rejects_same_branch():
    with SessionLocal() as db:
        run = _seed_run(db)
        run_id = run.id
        _seed_turns(AgentMessageBus(db), run_id)
        db.commit()
        with pytest.raises(ValueError, match="must differ"):
            branch_from_step(db, run_id=run_id, fork_turn_id=0, new_branch_id="main")


def test_fork_rejects_unknown_run():
    with SessionLocal() as db:
        with pytest.raises(ValueError, match="run not found"):
            branch_from_step(db, run_id="nope", fork_turn_id=0, new_branch_id="x")


def test_fork_rejects_when_no_events_in_range():
    with SessionLocal() as db:
        run = _seed_run(db)
        run_id = run.id
        AgentMessageBus(db).publish(
            BusEnvelope(run_id=run_id, turn_id=5, agent="planner", type="plan", payload={})
        )
        db.commit()
        with pytest.raises(ValueError, match="no events"):
            branch_from_step(db, run_id=run_id, fork_turn_id=0, new_branch_id="x")
