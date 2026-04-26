"""V25-06 — branch_exec re-execute + diff tests."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_branch_exec_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope
from secops.db import Base, SessionLocal, engine
from secops.models import BusEvent, Engagement, WorkspaceRun
from secops.replay.branch_exec import re_execute
from secops.replay.diff import diff_branches


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _seed(db) -> WorkspaceRun:
    eng = Engagement(name="be", mode="pentest", target="x", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
    db.add(run)
    db.flush()
    bus = AgentMessageBus(db)
    bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="planner", type="plan",
                            payload={"actions": [{"action_type": "recon", "objective": "p"}]}))
    bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="executor", type="action", payload={"a": 1}))
    bus.publish(BusEnvelope(run_id=run.id, turn_id=1, agent="planner", type="plan",
                            payload={"actions": [{"action_type": "exploit", "objective": "go"}]}))
    bus.publish(BusEnvelope(run_id=run.id, turn_id=1, agent="executor", type="observation",
                            payload={"status": "completed", "summary": "found"}))
    db.commit()
    return run


def test_re_execute_copies_then_replays_tail():
    with SessionLocal() as db:
        run = _seed(db)
        run_id = run.id

    with SessionLocal() as db:
        result = re_execute(db, run_id=run_id, fork_turn_id=0, new_branch_id="alt")
        db.commit()
    assert result.copied_count == 2  # turn_id == 0 events
    assert result.re_executed_count == 2  # turn_id == 1 events
    # No runner / no overrides → branches should be identical.
    assert all(d.kind == "identical" for d in result.diffs), [d.summary for d in result.diffs]


def test_re_execute_with_override_changes_plan_actions():
    with SessionLocal() as db:
        run = _seed(db)
        run_id = run.id

    def runner(ev, override):
        if not override:
            return None
        if ev.type == "plan_proposed":
            return {"actions": override.get("actions", ev.payload_json.get("actions", []))}
        return None

    with SessionLocal() as db:
        result = re_execute(
            db,
            run_id=run_id,
            fork_turn_id=0,
            new_branch_id="alt",
            runner=runner,
            overrides={1: {"actions": [{"action_type": "report", "objective": "stop"}]}},
        )
        db.commit()
    plan_diffs = [d for d in result.diffs if d.kind == "plan_actions_changed"]
    assert plan_diffs, [d.summary for d in result.diffs]
    detail = plan_diffs[0].detail
    assert any(a["action_type"] == "report" for a in detail["added"])
    assert any(a["action_type"] == "exploit" for a in detail["removed"])


def test_diff_branches_marks_observation_change():
    with SessionLocal() as db:
        run = _seed(db)
        run_id = run.id

    def runner(ev, _override):
        if ev.type == "observation_recorded":
            return {"status": "failed", "summary": "regressed"}
        return None

    with SessionLocal() as db:
        re_execute(db, run_id=run_id, fork_turn_id=0, new_branch_id="alt", runner=runner)
        db.commit()
    with SessionLocal() as db:
        diffs = diff_branches(db, run_id=run_id, base_branch="main", other_branch="alt")
    obs_diff = [d for d in diffs if d.kind == "observation_changed"]
    assert obs_diff
    assert obs_diff[0].detail["lhs_status"] == "completed"
    assert obs_diff[0].detail["rhs_status"] == "failed"
