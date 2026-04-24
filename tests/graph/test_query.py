"""V2-14 — attack-graph query API."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_graph_query_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.db import Base, SessionLocal, engine
from secops.graph import query
from secops.models import AttackGraphEdge, AttackGraphNode, Engagement, WorkspaceRun


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="gq", mode="pentest", target="10.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="10.0.0.1")
    db.add(run)
    db.flush()
    return run


def _add_node(db, run_id, node_type, stable_key, *, label="", confidence=0.5, metadata=None):
    n = AttackGraphNode(
        run_id=run_id, node_type=node_type, stable_key=stable_key, label=label or stable_key,
        confidence=confidence, metadata_json=metadata or {},
    )
    db.add(n)
    db.flush()
    return n


def _add_edge(db, run_id, src, dst, edge_type, *, confidence=0.5, metadata=None):
    e = AttackGraphEdge(
        run_id=run_id, source_node_id=src.id, target_node_id=dst.id, edge_type=edge_type,
        confidence=confidence, metadata_json=metadata or {},
    )
    db.add(e)
    db.flush()
    return e


def test_services_endpoints_cves_partition_by_type():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        _add_node(db, run_id, "target", "t:10.0.0.1")
        _add_node(db, run_id, "service", "s:10.0.0.1:80")
        _add_node(db, run_id, "service", "s:10.0.0.1:443")
        _add_node(db, run_id, "endpoint", "e:/admin")
        _add_node(db, run_id, "cve", "cve:CVE-2024-0001")
        db.commit()
        assert len(query.services_for_run(db, run_id)) == 2
        assert len(query.endpoints_for_run(db, run_id)) == 1
        assert len(query.cves_for_run(db, run_id)) == 1


def test_open_hypotheses_excludes_refuted_and_validated():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        target = _add_node(db, run_id, "target", "t")
        open_h = _add_node(db, run_id, "hypothesis", "h:open", label="open")
        refuted_h = _add_node(db, run_id, "hypothesis", "h:refuted", label="refuted")
        validated_h = _add_node(db, run_id, "hypothesis", "h:validated", label="validated",
                                metadata={"validated": True})
        neg = _add_node(db, run_id, "negative_evidence", "n:x")
        _add_edge(db, run_id, target, refuted_h, "has_hypothesis")
        _add_edge(db, run_id, neg, refuted_h, "refutes")
        _add_edge(db, run_id, target, open_h, "has_hypothesis")
        _add_edge(db, run_id, target, validated_h, "has_hypothesis")
        db.commit()
        open_ids = {h.stable_key for h in query.open_hypotheses(db, run_id)}
        assert open_ids == {"h:open"}


def test_unexplored_services_excludes_services_with_endpoints_or_cves():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        target = _add_node(db, run_id, "target", "t")
        explored = _add_node(db, run_id, "service", "s:explored")
        bare = _add_node(db, run_id, "service", "s:bare")
        endpoint = _add_node(db, run_id, "endpoint", "e:/a")
        _add_edge(db, run_id, target, explored, "exposes")
        _add_edge(db, run_id, target, bare, "exposes")
        # explored has an outgoing edge to an endpoint beyond the target->service discovery
        _add_edge(db, run_id, explored, endpoint, "has_endpoint")
        db.commit()
        keys = {n.stable_key for n in query.unexplored_services(db, run_id)}
        assert keys == {"s:bare"}


def test_neighbors_direction():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        a = _add_node(db, run_id, "service", "a")
        b = _add_node(db, run_id, "endpoint", "b")
        c = _add_node(db, run_id, "cve", "c")
        _add_edge(db, run_id, a, b, "has_endpoint")
        _add_edge(db, run_id, c, a, "has_intel")
        db.commit()
        outs = query.neighbors(db, run_id, a.id, direction="out")
        ins = query.neighbors(db, run_id, a.id, direction="in")
        both = query.neighbors(db, run_id, a.id, direction="both")
    assert [n.label for _, n in outs] == ["b"]
    assert [n.label for _, n in ins] == ["c"]
    assert {n.label for _, n in both} == {"b", "c"}


def test_neighbors_rejects_bad_direction():
    with SessionLocal() as db:
        run_id = _mk_run(db).id
        with pytest.raises(ValueError, match="direction"):
            query.neighbors(db, run_id, "nope", direction="sideways")
