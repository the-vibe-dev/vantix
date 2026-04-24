"""V2-20 — decision-graph builder."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_decision_graph_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest
from fastapi import HTTPException

from secops.bus.bus import AgentMessageBus
from secops.bus.messages import BusEnvelope
from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, WorkspaceRun
from secops.routers.runs import get_decision_graph
from secops.services.decision_graph import build_decision_graph


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="dg", mode="pentest", target="x", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
    db.add(run)
    db.flush()
    return run


def _seed(db, run_id):
    bus = AgentMessageBus(db)
    bus.publish(BusEnvelope(run_id=run_id, turn_id=0, agent="planner", type="plan", payload={"actions": [1, 2]}))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=0, agent="executor", type="action", payload={"action_type": "network"}))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=0, agent="executor", type="observation", payload={"status": "completed"},
                            caused_by_fact_ids=["fact_a"]))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=0, agent="evaluator", type="critique", payload={"should_replan": True}))
    bus.publish(BusEnvelope(run_id=run_id, turn_id=1, agent="planner", type="plan", payload={"actions": [1]}, parent_turn_id=0))


def test_decision_graph_basic_structure():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        _seed(db, run_id)
        db.commit()
        g = build_decision_graph(db, run_id)
    assert len(g.nodes) == 5
    # intra-turn predecessors: 3 edges in turn 0 (between 4 events) + 0 in turn 1
    intra = [e for e in g.edges if e.kind == "turn_predecessor"]
    causal = [e for e in g.edges if e.kind == "causal_fact"]
    assert len(intra) == 3
    assert len(causal) == 1
    # causal points from turn 0's last event (critique) → turn 1's plan
    assert causal[0].to_id == g.nodes[-1].id


def test_decision_graph_filters_by_fact_ids():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        _seed(db, run_id)
        db.commit()
        g = build_decision_graph(db, run_id, fact_ids=["fact_a"])
    # The observation event caused by fact_a plus its turn-0 ancestors.
    types = [n.type for n in g.nodes]
    assert "observation" in types
    # All selected nodes are in turn 0
    assert all(n.turn_id == 0 for n in g.nodes)


def test_decision_graph_empty_run():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        db.commit()
        g = build_decision_graph(db, run_id)
    assert g.nodes == [] and g.edges == []


def test_decision_graph_endpoint_404():
    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            get_decision_graph(run_id="nope", branch_id="main", fact_ids=None, db=db)
        assert exc.value.status_code == 404


def test_decision_graph_endpoint_returns_dict():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        _seed(db, run_id)
        db.commit()
        out = get_decision_graph(run_id=run_id, branch_id="main", fact_ids=None, db=db)
    assert out["run_id"] == run_id
    assert out["node_count"] == 5
    assert isinstance(out["edges"], list)
