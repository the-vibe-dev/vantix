"""P1-6 — Screenshot artifact IDs flow onto ``Finding.evidence_ids``.

``finding_promotion`` reads ``evidence_artifact_ids`` off the source fact's
metadata. Browser-emitted vectors stamp the screenshot artifact row's primary
key there at phase time; this test exercises the promotion contract without
pulling Playwright into the loop.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_browser_linkage_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

from secops import config as config_module
from secops.db import Base, SessionLocal, engine
from secops.models import Artifact, Engagement, Fact, WorkspaceRun
from secops.services.finding_promotion import FindingPromotionService


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="Browser Linkage", mode="pentest", target="https://app.test", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(
        engagement_id=eng.id,
        mode="pentest",
        workspace_id=f"ws-{eng.id[:8]}",
        status="running",
        objective="browser linkage",
        target="https://app.test",
        config_json={},
    )
    db.add(run)
    db.flush()
    return run


def _set_gate(value: bool) -> bool:
    old = config_module.settings.require_validated_promotion
    object.__setattr__(config_module.settings, "require_validated_promotion", value)
    return old


def test_promotion_carries_screenshot_artifact_id_into_evidence_ids() -> None:
    _reset_db()
    old = _set_gate(False)
    try:
        with SessionLocal() as db:
            run = _mk_run(db)
            shot = Artifact(run_id=run.id, kind="screenshot", path="artifacts/browser/001_home.png", metadata_json={"phase": "browser-assessment"})
            db.add(shot)
            db.flush()
            fact = Fact(
                run_id=run.id,
                source="browser-runtime",
                kind="vector",
                value="Hidden admin surface",
                confidence=0.78,
                tags=["browser", "admin-surface"],
                metadata_json={
                    "title": "Hidden admin surface",
                    "severity": "high",
                    "evidence": "/admin linked from home",
                    "evidence_artifact_ids": [shot.id],
                },
                validated=True,
                fingerprint="fp-admin-surface",
            )
            db.add(fact)
            db.flush()
            svc = FindingPromotionService()
            finding = svc.promote(db, run, {"source_kind": "vector", "source_id": fact.id})
            assert fact.id in finding.evidence_ids
            assert shot.id in finding.evidence_ids, "screenshot artifact id must be linked as evidence"
    finally:
        _set_gate(old)


def test_dedup_merge_accumulates_screenshot_artifact_ids() -> None:
    _reset_db()
    old = _set_gate(False)
    try:
        with SessionLocal() as db:
            run = _mk_run(db)
            shot_a = Artifact(run_id=run.id, kind="screenshot", path="a.png")
            shot_b = Artifact(run_id=run.id, kind="screenshot", path="b.png")
            db.add_all([shot_a, shot_b])
            db.flush()
            fp = "fp-dup"
            fact_a = Fact(
                run_id=run.id, source="browser-runtime", kind="vector", value="dup",
                confidence=0.5, tags=["browser"], validated=True, fingerprint=fp,
                metadata_json={"title": "dup", "severity": "medium", "evidence_artifact_ids": [shot_a.id]},
            )
            fact_b = Fact(
                run_id=run.id, source="browser-runtime", kind="vector", value="dup",
                confidence=0.5, tags=["browser"], validated=True, fingerprint=fp,
                metadata_json={"title": "dup", "severity": "medium", "evidence_artifact_ids": [shot_b.id]},
            )
            db.add_all([fact_a, fact_b])
            db.flush()
            svc = FindingPromotionService()
            first = svc.promote(db, run, {"source_kind": "vector", "source_id": fact_a.id})
            second = svc.promote(db, run, {"source_kind": "vector", "source_id": fact_b.id})
            assert first.id == second.id
            assert set(second.evidence_ids or []) >= {fact_a.id, fact_b.id, shot_a.id, shot_b.id}
    finally:
        _set_gate(old)


def test_scalar_screenshot_key_also_recognized() -> None:
    _reset_db()
    old = _set_gate(False)
    try:
        with SessionLocal() as db:
            run = _mk_run(db)
            shot = Artifact(run_id=run.id, kind="screenshot", path="single.png")
            db.add(shot)
            db.flush()
            fact = Fact(
                run_id=run.id, source="browser-runtime", kind="vector", value="single",
                confidence=0.6, tags=["browser"], validated=True, fingerprint="fp-single",
                metadata_json={"title": "single", "severity": "low", "screenshot_artifact_id": shot.id},
            )
            db.add(fact)
            db.flush()
            svc = FindingPromotionService()
            finding = svc.promote(db, run, {"source_kind": "vector", "source_id": fact.id})
            assert shot.id in finding.evidence_ids
    finally:
        _set_gate(old)
