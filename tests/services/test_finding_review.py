"""P2-3 + P2-5 — chain-of-custody columns populated and review transitions work."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_finding_review_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops import config as config_module
from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, Fact, RunEvent, User, WorkspaceRun
from secops.services.finding_promotion import FindingPromotionService
from secops.services.finding_review import FindingReviewService, ReviewError


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _set_gate(value: bool) -> bool:
    old = config_module.settings.require_validated_promotion
    object.__setattr__(config_module.settings, "require_validated_promotion", value)
    return old


def _seed(db) -> tuple[WorkspaceRun, User, Fact]:
    eng = Engagement(name="Review Test", mode="pentest", target="10.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(
        engagement_id=eng.id,
        mode="pentest",
        workspace_id=f"ws-{eng.id[:8]}",
        status="running",
        objective="review",
        target="10.0.0.1",
        config_json={},
    )
    user = User(username="alice", password_hash="x", role="operator")
    db.add_all([run, user])
    db.flush()
    fact = Fact(
        run_id=run.id, source="orchestrator", kind="vector", value="Reflected XSS",
        confidence=0.8, tags=["vector"], validated=True, fingerprint="fp-xss-1",
        metadata_json={"title": "Reflected XSS", "severity": "high", "evidence": "body echo"},
    )
    db.add(fact)
    db.flush()
    return run, user, fact


def test_promotion_stamps_promoted_at_and_default_draft():
    _reset_db()
    old = _set_gate(False)
    try:
        with SessionLocal() as db:
            run, _, fact = _seed(db)
            finding = FindingPromotionService().promote(db, run, {"source_kind": "vector", "source_id": fact.id})
            assert finding.disposition == "draft"
            assert finding.promoted_at is not None
            assert finding.reviewed_at is None
            assert finding.reviewer_user_id is None
    finally:
        _set_gate(old)


def test_review_transitions_draft_to_confirmed():
    _reset_db()
    old = _set_gate(False)
    try:
        with SessionLocal() as db:
            run, user, fact = _seed(db)
            finding = FindingPromotionService().promote(db, run, {"source_kind": "vector", "source_id": fact.id})
            reviewed = FindingReviewService().review(
                db, run, finding.id, reviewer_username=user.username,
                disposition="confirmed", note="looks real",
            )
            assert reviewed.disposition == "confirmed"
            assert reviewed.reviewer_user_id == user.id
            assert reviewed.reviewed_at is not None
            events = db.query(RunEvent).filter(RunEvent.run_id == run.id, RunEvent.event_type == "finding_reviewed").all()
            assert len(events) == 1
    finally:
        _set_gate(old)


def test_terminal_disposition_rejects_transitions():
    _reset_db()
    old = _set_gate(False)
    try:
        with SessionLocal() as db:
            run, user, fact = _seed(db)
            finding = FindingPromotionService().promote(db, run, {"source_kind": "vector", "source_id": fact.id})
            svc = FindingReviewService()
            svc.review(db, run, finding.id, reviewer_username=user.username, disposition="dismissed")
            with pytest.raises(ReviewError):
                svc.review(db, run, finding.id, reviewer_username=user.username, disposition="confirmed")
    finally:
        _set_gate(old)


def test_invalid_disposition_rejected():
    _reset_db()
    old = _set_gate(False)
    try:
        with SessionLocal() as db:
            run, user, fact = _seed(db)
            finding = FindingPromotionService().promote(db, run, {"source_kind": "vector", "source_id": fact.id})
            with pytest.raises(ReviewError):
                FindingReviewService().review(
                    db, run, finding.id, reviewer_username=user.username, disposition="approved",
                )
    finally:
        _set_gate(old)


def test_unknown_reviewer_still_stamps_username_via_event():
    _reset_db()
    old = _set_gate(False)
    try:
        with SessionLocal() as db:
            run, _, fact = _seed(db)
            finding = FindingPromotionService().promote(db, run, {"source_kind": "vector", "source_id": fact.id})
            reviewed = FindingReviewService().review(
                db, run, finding.id, reviewer_username="stranger", disposition="reviewed",
            )
            # Unknown usernames resolve reviewer_user_id to None but review still succeeds.
            assert reviewed.reviewer_user_id is None
            assert reviewed.disposition == "reviewed"
    finally:
        _set_gate(old)
