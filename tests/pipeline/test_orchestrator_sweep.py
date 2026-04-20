from __future__ import annotations

import os
import tempfile
import threading
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_pipeline_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, Fact, WorkspaceRun
from secops.services.execution import ExecutionManager
from secops.services.fingerprint import compute_fingerprint


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        if self.path == "/ok":
            body = b"pwn marker present"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def http_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="Sweep Test", mode="pentest", target="127.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(
        engagement_id=eng.id,
        mode="pentest",
        workspace_id=f"ws-{eng.id[:8]}",
        status="running",
        objective="sweep test",
        target="127.0.0.1",
        config_json={},
    )
    db.add(run)
    db.flush()
    return run


def test_sweep_validates_vectors_with_replay_spec(http_server):
    _reset_db()
    with SessionLocal() as db:
        run = _mk_run(db)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=1)

        # Vector with replay spec pointing at a real response that matches expectations.
        with_replay = Fact(
            run_id=run.id,
            source="orchestrator",
            kind="vector",
            value="reflected marker",
            confidence=0.7,
            tags=["vector"],
            metadata_json={
                "title": "marker present",
                "url": f"{http_server}/ok",
                "replay": {
                    "type": "http",
                    "method": "GET",
                    "url": f"{http_server}/ok",
                    "expect": {"status": 200, "body_contains": "pwn marker"},
                },
            },
        )
        # Vector without replay spec — should not be validated.
        without_replay = Fact(
            run_id=run.id,
            source="orchestrator",
            kind="vector",
            value="hypothesis",
            confidence=0.4,
            tags=["vector"],
            metadata_json={"title": "hypothesis", "url": f"{http_server}/ok"},
        )
        db.add_all([with_replay, without_replay])
        db.flush()

        svc = ExecutionManager.__new__(ExecutionManager)
        svc.events = __import__("secops.services.events", fromlist=["RunEventService"]).RunEventService()
        svc._sweep_orchestrator_vectors(db, run, session_started_at=cutoff)
        db.flush()

        db.refresh(with_replay)
        db.refresh(without_replay)
        assert with_replay.validated is True
        assert with_replay.fingerprint  # fingerprint backfilled
        assert without_replay.validated is False
        assert without_replay.fingerprint  # fingerprint backfilled even without replay


def test_sweep_records_refutation_as_negative_evidence(http_server):
    _reset_db()
    with SessionLocal() as db:
        run = _mk_run(db)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=1)
        vec = Fact(
            run_id=run.id,
            source="orchestrator",
            kind="vector",
            value="will refute",
            confidence=0.6,
            tags=["vector"],
            metadata_json={
                "url": f"{http_server}/ok",
                "replay": {
                    "type": "http",
                    "method": "GET",
                    "url": f"{http_server}/ok",
                    "expect": {"status": 200, "body_contains": "NOT_PRESENT"},
                },
            },
        )
        db.add(vec)
        db.flush()
        svc = ExecutionManager.__new__(ExecutionManager)
        svc.events = __import__("secops.services.events", fromlist=["RunEventService"]).RunEventService()
        svc._sweep_orchestrator_vectors(db, run, session_started_at=cutoff)
        db.flush()
        db.refresh(vec)
        assert vec.validated is False
        # A negative_evidence Fact with matching fingerprint should exist.
        assert vec.fingerprint
        neg = db.query(Fact).filter(
            Fact.run_id == run.id,
            Fact.kind == "negative_evidence",
            Fact.fingerprint == vec.fingerprint,
        ).one()
        assert neg.metadata_json["source_fact_id"] == vec.id
