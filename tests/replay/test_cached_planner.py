"""V25-05 — CachedPlannerAgent + LlmCacheEntry wiring tests."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_cached_planner_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.agents.base import RunState
from secops.agents.planner import CachedPlannerAgent, ReplayCacheMiss
from secops.bus.messages import Plan, ProposedAction
from secops.db import Base, SessionLocal, engine


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _make_plan(turn_id: int) -> Plan:
    return Plan(
        turn_id=turn_id,
        rationale="ok",
        actions=[ProposedAction(action_type="recon", objective="probe")],
    )


def test_cached_planner_stores_then_hits():
    calls = {"n": 0}

    def plan_fn(state: RunState) -> Plan:
        calls["n"] += 1
        return _make_plan(state.turn_id)

    with SessionLocal() as db:
        planner = CachedPlannerAgent(
            plan_fn,
            db=db,
            model="test-model",
            prompt_fn=lambda s: {"prompt": s.run_id, "turn": s.turn_id},
            params_fn=lambda _s: {"temperature": 0.0},
        )
        state = RunState(run_id="r1", turn_id=0)
        first = planner.plan(state)
        db.commit()
        second = planner.plan(state)
        db.commit()

    assert first.actions[0].action_type == "recon"
    assert second.actions[0].action_type == "recon"
    assert calls["n"] == 1, "second invocation should hit the cache, not call plan_fn"


def test_cached_planner_strict_replay_misses_raise():
    def plan_fn(state: RunState) -> Plan:  # pragma: no cover
        raise AssertionError("should not be invoked in strict mode")

    with SessionLocal() as db:
        planner = CachedPlannerAgent(
            plan_fn,
            db=db,
            model="test-model",
            prompt_fn=lambda s: {"turn": s.turn_id},
            require_cache=True,
        )
        with pytest.raises(ReplayCacheMiss):
            planner.plan(RunState(run_id="r1", turn_id=0))


def test_cached_planner_strict_replay_hits_succeed():
    def plan_fn(state: RunState) -> Plan:
        return _make_plan(state.turn_id)

    with SessionLocal() as db:
        warm = CachedPlannerAgent(
            plan_fn,
            db=db,
            model="test-model",
            prompt_fn=lambda s: {"turn": s.turn_id},
        )
        warm.plan(RunState(run_id="r1", turn_id=0))
        db.commit()

    with SessionLocal() as db:
        strict = CachedPlannerAgent(
            lambda _s: (_ for _ in ()).throw(AssertionError("must not run")),  # type: ignore[arg-type]
            db=db,
            model="test-model",
            prompt_fn=lambda s: {"turn": s.turn_id},
            require_cache=True,
        )
        replayed = strict.plan(RunState(run_id="r1", turn_id=0))
    assert replayed.actions[0].action_type == "recon"


def test_cached_planner_keys_on_prompt():
    def plan_fn(state: RunState) -> Plan:
        return _make_plan(state.turn_id)

    with SessionLocal() as db:
        planner = CachedPlannerAgent(
            plan_fn,
            db=db,
            model="test-model",
            prompt_fn=lambda s: {"turn": s.turn_id},
        )
        planner.plan(RunState(run_id="r1", turn_id=0))
        db.commit()

    with SessionLocal() as db:
        strict = CachedPlannerAgent(
            plan_fn,
            db=db,
            model="test-model",
            prompt_fn=lambda s: {"turn": s.turn_id + 1},  # different prompt -> miss
            require_cache=True,
        )
        with pytest.raises(ReplayCacheMiss):
            strict.plan(RunState(run_id="r1", turn_id=0))
