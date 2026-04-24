"""V2-15 — graph-fed planner frontier."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_graph_frontier_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.db import Base, SessionLocal, engine
from secops.graph.frontier import build_frontier
from secops.models import AttackGraphEdge, AttackGraphNode, Engagement, WorkspaceRun


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="fr", mode="pentest", target="10.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="10.0.0.1")
    db.add(run)
    db.flush()
    return run


def _n(db, run_id, nt, key, **kw):
    n = AttackGraphNode(run_id=run_id, node_type=nt, stable_key=key, label=key,
                        confidence=kw.pop("confidence", 0.7), metadata_json=kw)
    db.add(n); db.flush(); return n


def _e(db, run_id, s, t, et, **kw):
    e = AttackGraphEdge(run_id=run_id, source_node_id=s.id, target_node_id=t.id, edge_type=et,
                        confidence=kw.pop("confidence", 0.7), metadata_json=kw)
    db.add(e); db.flush(); return e


def test_frontier_includes_unexplored_services_and_open_hypotheses():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        target = _n(db, run_id, "target", "t")
        bare_svc = _n(db, run_id, "service", "s:bare")
        open_hyp = _n(db, run_id, "hypothesis", "h:open", severity="high")
        _e(db, run_id, target, bare_svc, "exposes")
        _e(db, run_id, target, open_hyp, "has_hypothesis")
        db.commit()
        frontier = build_frontier(db, run_id)
    kinds = {item.kind for item in frontier}
    assert "unexplored_service" in kinds
    assert "open_hypothesis" in kinds
    # Open hypothesis with high severity should rank above bare service
    ranks = [(i.kind, i.score) for i in frontier]
    assert ranks == sorted(ranks, key=lambda x: -x[1])


def test_frontier_limit_applied():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        target = _n(db, run_id, "target", "t")
        for i in range(30):
            svc = _n(db, run_id, "service", f"s:{i}")
            _e(db, run_id, target, svc, "exposes")
        db.commit()
        frontier = build_frontier(db, run_id, limit=5)
    assert len(frontier) == 5


def test_frontier_is_deterministic():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        target = _n(db, run_id, "target", "t")
        s1 = _n(db, run_id, "service", "s:1")
        s2 = _n(db, run_id, "service", "s:2")
        cve = _n(db, run_id, "cve", "cve:X", severity="high", public_exploit=True)
        _e(db, run_id, target, s1, "exposes")
        _e(db, run_id, target, s2, "exposes")
        _e(db, run_id, cve, s1, "has_intel")
        db.commit()
        a = [i.as_dict() for i in build_frontier(db, run_id)]
        b = [i.as_dict() for i in build_frontier(db, run_id)]
    assert a == b
