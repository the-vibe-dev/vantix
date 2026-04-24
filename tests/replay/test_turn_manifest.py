"""V2-12 — replay turn manifest."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_turn_manifest_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope
from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, WorkspaceRun
from secops.replay.turn_manifest import (
    REPLAY_TURN_SCHEMA_VERSION,
    build_turn_manifest,
    write_turn_manifest,
)


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _seed_run(db) -> WorkspaceRun:
    eng = Engagement(name="tm", mode="pentest", target="x", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
    db.add(run)
    db.flush()
    return run


def test_manifest_captures_all_turns_in_order():
    with SessionLocal() as db:
        run = _seed_run(db)
        bus = AgentMessageBus(db)
        bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="planner", type="plan", payload={"n": 1}))
        bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="executor", type="action", payload={"a": 1}))
        bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="executor", type="observation", payload={"ok": True}))
        bus.publish(BusEnvelope(run_id=run.id, turn_id=1, agent="planner", type="plan", payload={"n": 2}))
        db.commit()
        m = build_turn_manifest(db, run)
    assert m["schema_version"] == REPLAY_TURN_SCHEMA_VERSION
    assert m["turn_count"] == 4
    seqs = [t["seq"] for t in m["turns"]]
    assert seqs == sorted(seqs)
    assert all(len(t["msg_sha256"]) == 64 for t in m["turns"])


def test_manifest_is_deterministic():
    with SessionLocal() as db:
        run = _seed_run(db)
        bus = AgentMessageBus(db)
        bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="planner", type="plan", payload={"x": 1}))
        db.commit()
        a = build_turn_manifest(db, run)
        b = build_turn_manifest(db, run)
    a.pop("generated_at"); b.pop("generated_at")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["chain_sha256"] == b["chain_sha256"]


def test_branch_filter_isolates_turns():
    with SessionLocal() as db:
        run = _seed_run(db)
        bus = AgentMessageBus(db)
        bus.publish(BusEnvelope(run_id=run.id, branch_id="main", turn_id=0, agent="planner", type="plan", payload={"n": 1}))
        bus.publish(BusEnvelope(run_id=run.id, branch_id="fork", turn_id=0, agent="planner", type="plan", payload={"n": 2}))
        db.commit()
        main = build_turn_manifest(db, run, branch_id="main")
        fork = build_turn_manifest(db, run, branch_id="fork")
    assert main["turn_count"] == 1 and main["branch_id"] == "main"
    assert fork["turn_count"] == 1 and fork["branch_id"] == "fork"
    assert main["chain_sha256"] != fork["chain_sha256"]


def test_payload_change_breaks_chain_hash():
    with SessionLocal() as db:
        run = _seed_run(db)
        bus = AgentMessageBus(db)
        bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="planner", type="plan", payload={"v": 1}))
        db.commit()
        m1 = build_turn_manifest(db, run)

    with SessionLocal() as db:
        run2 = _seed_run(db)
        bus = AgentMessageBus(db)
        bus.publish(BusEnvelope(run_id=run2.id, turn_id=0, agent="planner", type="plan", payload={"v": 2}))
        db.commit()
        m2 = build_turn_manifest(db, run2)

    assert m1["chain_sha256"] != m2["chain_sha256"]


def test_write_manifest_roundtrip(tmp_path):
    with SessionLocal() as db:
        run = _seed_run(db)
        bus = AgentMessageBus(db)
        bus.publish(BusEnvelope(run_id=run.id, turn_id=0, agent="planner", type="plan", payload={"a": 1}))
        db.commit()
        path = write_turn_manifest(db, run, tmp_path / "replay.v2.json")
    data = json.loads(path.read_text())
    assert data["turn_count"] == 1
    assert data["run_id"] == run.id
