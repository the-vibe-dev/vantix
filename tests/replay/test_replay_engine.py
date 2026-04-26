"""V25-05 — replay execution engine tests."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_replay_engine_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope
from secops.db import Base, SessionLocal, engine
from secops.models import BusEvent, Engagement, ReplayDiff, ReplayRun, ReplayStep, WorkspaceRun
from secops.replay.engine import replay
from secops.replay.spec import materialize


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _seed(db) -> WorkspaceRun:
    eng = Engagement(name="re", mode="pentest", target="x", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
    db.add(run)
    db.flush()
    bus = AgentMessageBus(db)
    bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="planner", type="plan", payload={"n": 1}))
    bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="executor", type="action", payload={"a": 1}))
    bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="executor", type="observation", payload={"ok": True}))
    bus.publish(BusEnvelope(run_id=run.id, turn_id=1, agent="planner", type="plan", payload={"n": 2}))
    db.commit()
    return run


def test_replay_clean_run_zero_divergences():
    with SessionLocal() as db:
        run = _seed(db)
        record = materialize(db, run)
        db.commit()
        spec_id = record.spec_id
    with SessionLocal() as db:
        outcome = replay(db, spec_id)
        db.commit()
    assert outcome.divergence_count == 0
    assert outcome.status == "passed"
    assert len(outcome.steps) == 4
    with SessionLocal() as db:
        assert db.query(ReplayRun).filter_by(id=outcome.replay_run_id).one().status == "passed"
        assert db.query(ReplayStep).filter_by(replay_run_id=outcome.replay_run_id).count() == 4
        assert db.query(ReplayDiff).filter_by(replay_run_id=outcome.replay_run_id).count() == 0


def test_replay_detects_payload_tamper():
    with SessionLocal() as db:
        run = _seed(db)
        record = materialize(db, run)
        db.commit()
        spec_id = record.spec_id
        run_id = run.id
    # Mutate one bus event's payload — should diverge at exactly that turn.
    with SessionLocal() as db:
        ev = db.query(BusEvent).filter_by(run_id=run_id, seq=2).one()
        ev.payload_json = {"a": 999}
        db.commit()
    with SessionLocal() as db:
        outcome = replay(db, spec_id)
        db.commit()
    assert outcome.divergence_count == 1
    assert outcome.status == "diverged"
    diverged = [s for s in outcome.steps if s.diverged]
    assert len(diverged) == 1
    assert diverged[0].seq == 2
    assert diverged[0].divergence_kind == "envelope_sha_mismatch"


def test_replay_detects_missing_event():
    with SessionLocal() as db:
        run = _seed(db)
        record = materialize(db, run)
        db.commit()
        spec_id = record.spec_id
        run_id = run.id
    with SessionLocal() as db:
        ev = db.query(BusEvent).filter_by(run_id=run_id, seq=3).one()
        db.delete(ev)
        db.commit()
    with SessionLocal() as db:
        outcome = replay(db, spec_id)
        db.commit()
    assert outcome.divergence_count == 1
    assert outcome.steps[2].divergence_kind == "missing_event"


def test_replay_walks_to_end_on_divergence():
    with SessionLocal() as db:
        run = _seed(db)
        record = materialize(db, run)
        db.commit()
        spec_id = record.spec_id
        run_id = run.id
    with SessionLocal() as db:
        for ev in db.query(BusEvent).filter_by(run_id=run_id).all():
            ev.payload_json = {"mutated": True}
        db.commit()
    with SessionLocal() as db:
        outcome = replay(db, spec_id)
        db.commit()
    assert outcome.divergence_count == 4
    assert len(outcome.steps) == 4
