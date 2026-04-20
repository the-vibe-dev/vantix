from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_pipeline_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops import config as config_module
from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, Fact, Finding, RunEvent, WorkspaceRun
from secops.services.finding_promotion import (
    FindingPromotionService,
    SuppressedByNegativeEvidence,
    ValidationRequired,
)
from secops.services.fingerprint import compute_fingerprint


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _mk_run(db) -> WorkspaceRun:
    eng = Engagement(name="Promotion Test", mode="pentest", target="10.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(
        engagement_id=eng.id,
        mode="pentest",
        workspace_id=f"ws-{eng.id[:8]}",
        status="running",
        objective="validate promotion gates",
        target="10.0.0.1",
        config_json={},
    )
    db.add(run)
    db.flush()
    return run


def _mk_vector(db, run: WorkspaceRun, *, validated: bool, fingerprint: str | None, meta: dict | None = None) -> Fact:
    fact = Fact(
        run_id=run.id,
        source="orchestrator",
        kind="vector",
        value="Reflected XSS on /search",
        confidence=0.8,
        tags=["vector"],
        metadata_json=meta or {"title": "Reflected XSS", "severity": "high", "evidence": "body echo"},
        validated=validated,
        fingerprint=fingerprint,
    )
    db.add(fact)
    db.flush()
    return fact


def _set_gate(value: bool) -> bool:
    old = config_module.settings.require_validated_promotion
    object.__setattr__(config_module.settings, "require_validated_promotion", value)
    return old


@pytest.fixture
def gate_off():
    old = _set_gate(False)
    try:
        yield
    finally:
        _set_gate(old)


@pytest.fixture
def gate_on():
    old = _set_gate(True)
    try:
        yield
    finally:
        _set_gate(old)


def test_validation_gate_blocks_unvalidated_vector(gate_on):
    _reset_db()
    with SessionLocal() as db:
        run = _mk_run(db)
        fp = compute_fingerprint(vector_kind="xss", target_host="10.0.0.1", target_path="/search", target_param="q", cwe="79")
        fact = _mk_vector(db, run, validated=False, fingerprint=fp)
        svc = FindingPromotionService()
        with pytest.raises(ValidationRequired):
            svc.promote(db, run, {"source_kind": "vector", "source_id": fact.id})


def test_validation_gate_allows_validated_vector(gate_on):
    _reset_db()
    with SessionLocal() as db:
        run = _mk_run(db)
        fp = compute_fingerprint(vector_kind="xss", target_host="10.0.0.1", target_path="/search", target_param="q", cwe="79")
        fact = _mk_vector(db, run, validated=True, fingerprint=fp)
        svc = FindingPromotionService()
        finding = svc.promote(db, run, {"source_kind": "vector", "source_id": fact.id})
        assert finding.fingerprint == fp
        assert finding.evidence_ids == [fact.id]


def test_negative_evidence_suppresses_promotion(gate_off):
    _reset_db()
    with SessionLocal() as db:
        run = _mk_run(db)
        fp = compute_fingerprint(vector_kind="sqli", target_host="10.0.0.1", target_path="/api/users", target_param="id", cwe="89")
        fact = _mk_vector(db, run, validated=True, fingerprint=fp)
        # Newer negative_evidence with matching fingerprint.
        neg = Fact(
            run_id=run.id,
            source="exploit_validation",
            kind="negative_evidence",
            value="payload rejected",
            confidence=0.9,
            tags=["negative_evidence"],
            metadata_json={"fingerprint": fp, "reason": "WAF blocked"},
            validated=True,
            fingerprint=fp,
        )
        db.add(neg)
        db.flush()
        svc = FindingPromotionService()
        with pytest.raises(SuppressedByNegativeEvidence):
            svc.promote(db, run, {"source_kind": "vector", "source_id": fact.id})
        # suppression event emitted
        events = db.query(RunEvent).filter(RunEvent.run_id == run.id, RunEvent.event_type == "finding_suppressed").all()
        assert len(events) == 1


def test_dedup_merges_by_fingerprint(gate_off):
    _reset_db()
    with SessionLocal() as db:
        run = _mk_run(db)
        fp = compute_fingerprint(vector_kind="idor", target_host="10.0.0.1", target_path="/api/orders", target_param="id", cwe="639")
        fact_a = _mk_vector(db, run, validated=True, fingerprint=fp)
        fact_b = _mk_vector(db, run, validated=True, fingerprint=fp)
        svc = FindingPromotionService()
        first = svc.promote(db, run, {"source_kind": "vector", "source_id": fact_a.id})
        second = svc.promote(db, run, {"source_kind": "vector", "source_id": fact_b.id})
        assert first.id == second.id
        # evidence_ids accrues both facts
        assert set(second.evidence_ids or []) == {fact_a.id, fact_b.id}
        # one dedup_merged event
        events = db.query(RunEvent).filter(RunEvent.run_id == run.id, RunEvent.event_type == "dedup_merged").all()
        assert len(events) == 1
        # only one finding in the run
        findings = db.query(Finding).filter(Finding.run_id == run.id).all()
        assert len(findings) == 1


def test_fingerprint_derived_from_meta_when_missing(gate_off):
    _reset_db()
    with SessionLocal() as db:
        run = _mk_run(db)
        meta = {
            "title": "Open redirect",
            "severity": "medium",
            "evidence": "Location header leaks target",
            "vulnerability_class": "open-redirect",
            "url": "https://10.0.0.1/login?next=https://evil",
            "cwe": "601",
        }
        fact = _mk_vector(db, run, validated=True, fingerprint=None, meta=meta)
        svc = FindingPromotionService()
        finding = svc.promote(db, run, {"source_kind": "vector", "source_id": fact.id})
        assert finding.fingerprint
        assert fact.fingerprint == finding.fingerprint
