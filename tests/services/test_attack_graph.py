from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_attack_graph_test_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"
os.environ["SECOPS_RUNTIME_ROOT"] = str(Path(tempfile.gettempdir()) / f"secops_attack_graph_runtime_{os.getpid()}")

from secops.attack_graph.service import AttackGraphService
from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, Fact, Finding, WorkspaceRun


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed_run() -> WorkspaceRun:
    engagement = Engagement(name="Graph Test", mode="pentest", target="10.10.10.10")
    run = WorkspaceRun(
        engagement=engagement,
        mode="pentest",
        workspace_id="graph-test",
        status="running",
        target="10.10.10.10",
        objective="graph",
        config_json={},
    )
    return run


def test_attack_graph_syncs_facts_and_findings() -> None:
    reset_db()
    with SessionLocal() as db:
        run = _seed_run()
        db.add(run)
        db.flush()
        vector = Fact(
            run_id=run.id,
            source="browser",
            kind="vector",
            value="IDOR signal: GET /api/Users/:id",
            confidence=0.86,
            tags=["authz"],
            validated=True,
            fingerprint="f" * 64,
            metadata_json={"title": "IDOR signal"},
        )
        db.add_all(
            [
                Fact(run_id=run.id, source="recon", kind="port", value="3001", confidence=0.9),
                Fact(run_id=run.id, source="browser", kind="route", value="http://10.10.10.10:3001/#/login", confidence=0.8),
                Fact(run_id=run.id, source="cve", kind="cve", value="CVE-2025-0001", confidence=0.7),
                vector,
            ]
        )
        db.flush()
        finding = Finding(
            run_id=run.id,
            title="IDOR signal",
            severity="high",
            status="validated",
            confidence=0.86,
            fingerprint=vector.fingerprint,
            evidence_ids=[vector.id],
        )
        db.add(finding)
        db.commit()

        graph = AttackGraphService().read_run(db, run)
        db.commit()

        node_types = graph["summary"]["node_types"]
        edge_types = graph["summary"]["edge_types"]
        assert node_types["target"] == 1
        assert node_types["service"] >= 1
        assert node_types["endpoint"] == 1
        assert node_types["cve"] == 1
        assert node_types["hypothesis"] == 1
        assert node_types["finding"] == 1
        assert edge_types["has_endpoint"] == 1
        assert edge_types["validated_by"] == 1


def test_attack_graph_sync_is_idempotent() -> None:
    reset_db()
    with SessionLocal() as db:
        run = _seed_run()
        db.add(run)
        db.flush()
        db.add(Fact(run_id=run.id, source="recon", kind="service", value="ssh", confidence=0.8))
        db.commit()

        service = AttackGraphService()
        first = service.sync_run(db, run)
        second = service.sync_run(db, run)
        db.commit()

        assert first.nodes_created > 0
        assert second.nodes_created == 0
        assert second.edges_created == 0
