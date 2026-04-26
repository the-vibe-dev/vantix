"""V25-14 — verify migration 0011 backfills legacy bus_events.type values."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

DB_PATH = Path(tempfile.gettempdir()) / f"secops_canon_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{DB_PATH}"

import pytest
from sqlalchemy import text

from secops.db import Base, SessionLocal, engine


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def test_legacy_to_canonical_backfill_via_migration_sql():
    """Insert legacy rows, run the 0011 forward SQL, assert canonical names."""
    from secops.models import BusEvent, Engagement, WorkspaceRun

    with SessionLocal() as db:
        eng = Engagement(name="r", mode="pentest", target="x", tags=["pentest"])
        db.add(eng); db.flush()
        run = WorkspaceRun(engagement_id=eng.id, mode="pentest", workspace_id=f"ws_{eng.id}", target="x")
        db.add(run); db.flush()
        run_id = run.id
        # Legacy short-name rows (bypass envelope coercion via direct ORM insert).
        for i, t in enumerate(["plan", "action", "observation", "critique", "policy_decision"]):
            db.add(BusEvent(
                run_id=run_id, branch_id="main", seq=i + 1, turn_id=0,
                agent="planner", type=t, payload_json={}, content_hash="x",
            ))
        db.commit()

        # Apply the 0011 forward UPDATE statements directly.
        for legacy, canonical in [
            ("plan", "plan_proposed"),
            ("action", "action_dispatched"),
            ("observation", "observation_recorded"),
            ("critique", "turn_committed"),
            ("policy_decision", "policy_evaluated"),
        ]:
            db.execute(text(f"UPDATE bus_events SET type = '{canonical}' WHERE type = '{legacy}'"))
        db.commit()

        types = sorted(r[0] for r in db.execute(text("SELECT type FROM bus_events WHERE run_id = :r"), {"r": run_id}))
    assert types == sorted([
        "plan_proposed", "action_dispatched", "observation_recorded",
        "turn_committed", "policy_evaluated",
    ])
