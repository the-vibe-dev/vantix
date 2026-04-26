"""V2-10 — GET /runs/{run_id}/bus endpoint for policy-decision drawer."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_runs_bus_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest
from fastapi import HTTPException

from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope
from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, WorkspaceRun
from secops.routers.runs import list_run_bus_events


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="bus-endpoint", mode="pentest", target="x", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
    db.add(run)
    db.flush()
    return run


def _seed(db, run_id: str) -> None:
    bus = AgentMessageBus(db)
    bus.publish(BusEnvelope(run_id=run_id, turn_id=0, agent="planner", type="plan", payload={"n": 1}))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=0, agent="planner", type="policy_decision", payload={"verdict": "allow"}))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=0, agent="executor", type="action", payload={"k": "v"}))
    bus.publish(BusEnvelope(run_id=run_id, branch_id="alt", turn_id=0, agent="planner", type="plan", payload={"n": 2}))


def _call(db, run_id: str, *, branch_id="main", after_seq=0, type=None, agent=None, limit=200):
    return list_run_bus_events(
        run_id=run_id, branch_id=branch_id, after_seq=after_seq,
        type=type, agent=agent, limit=limit, db=db,
    )


def test_returns_all_events_for_branch():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        _seed(db, run_id)
        db.commit()
        rows = _call(db, run_id)
    types = [r.type for r in rows]
    assert types == ["plan_proposed", "policy_evaluated", "action_dispatched"]


def test_filters_by_type_and_agent():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        _seed(db, run_id)
        db.commit()
        rows = _call(db, run_id, type="policy_evaluated")
        assert [r.type for r in rows] == ["policy_evaluated"]
        rows = _call(db, run_id, agent="executor")
        assert [r.agent for r in rows] == ["executor"]


def test_after_seq_and_branch_filter():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        _seed(db, run_id)
        db.commit()
        rows = _call(db, run_id, after_seq=2)
        assert [r.seq for r in rows] == [3]
        alt = _call(db, run_id, branch_id="alt")
        assert len(alt) == 1 and alt[0].branch_id == "alt"


def test_404_on_missing_run():
    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            _call(db, "missing")
        assert exc.value.status_code == 404
