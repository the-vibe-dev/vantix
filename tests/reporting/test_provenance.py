"""P4-1 / P4-3 — reporter emits provenance manifest + signable attestation envelope."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

TEST_DB_PATH = Path(
    os.getenv(
        "SECOPS_TEST_DB",
        str(Path(tempfile.gettempdir()) / f"secops_reporting_provenance_{os.getpid()}.db"),
    )
)
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

from secops.db import Base, SessionLocal, engine
from secops.models import Artifact, Engagement, Finding, User, WorkspaceRun
from secops.services.reporting import ReportingService


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed(db, workspace_root: Path) -> WorkspaceRun:
    eng = Engagement(name="Provenance", mode="pentest", target="10.0.0.2", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(
        engagement_id=eng.id,
        mode="pentest",
        workspace_id=f"ws-{eng.id[:8]}",
        status="running",
        objective="provenance",
        target="10.0.0.2",
        config_json={},
    )
    user = User(id="user-bob", username="bob", password_hash="x", role="operator")
    db.add_all([run, user])
    db.flush()

    artifacts_dir = workspace_root / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    shot_path = artifacts_dir / "screenshot.png"
    shot_path.write_bytes(b"\x89PNG\r\n\x1a\nFAKE")
    art = Artifact(
        id="art-shot-1",
        run_id=run.id,
        kind="screenshot",
        path=str(shot_path),
    )
    db.add(art)

    finding = Finding(
        run_id=run.id,
        title="SQLi on /login",
        severity="critical",
        status="validated",
        summary="Tautology login bypass",
        evidence="' OR 1=1 -- returns admin session",
        reproduction="POST /login u=' OR 1=1 --&p=x",
        remediation="Use parameterized queries",
        confidence=0.95,
        fingerprint="fp-sqli-prov",
        evidence_ids=["art-shot-1"],
        reproduction_script="curl -d \"u=' OR 1=1 --&p=x\" https://target/login",
        promoted_at=datetime(2026, 4, 21, 10, 0, 0, tzinfo=timezone.utc),
        reviewed_at=datetime(2026, 4, 21, 11, 0, 0, tzinfo=timezone.utc),
        reviewer_user_id="user-bob",
        disposition="confirmed",
    )
    db.add(finding)
    db.flush()
    return run


def test_provenance_manifest_and_attestation(tmp_path: Path, monkeypatch) -> None:
    _reset_db()
    # Pin workspace root so artifact paths line up with the ReportingService's
    # resolved paths object.
    monkeypatch.setenv("SECOPS_WORKSPACE_ROOT", str(tmp_path))
    with SessionLocal() as db:
        run = _seed(db, tmp_path / "engagements" / "x" / "runs" / "x")
        db.commit()
        service = ReportingService()
        outputs = service.generate(db, run)

    prov_path = Path(outputs["provenance_path"])
    att_path = Path(outputs["attestation_path"])
    assert prov_path.is_file()
    assert att_path.is_file()

    prov = json.loads(prov_path.read_text())
    assert prov["schema_version"] == 1
    assert prov["kind"] == "vantix.finding_provenance.v1"
    assert prov["finding_count"] == 1
    row = prov["findings"][0]
    assert row["fingerprint"] == "fp-sqli-prov"
    assert row["disposition"] == "confirmed"
    assert row["reviewer_user_id"] == "user-bob"
    assert row["evidence_ids"] == ["art-shot-1"]
    # reproduction_script_sha256 matches independently recomputed digest.
    expected_repro_sha = hashlib.sha256(
        "curl -d \"u=' OR 1=1 --&p=x\" https://target/login".encode("utf-8")
    ).hexdigest()
    assert row["reproduction_script_sha256"] == expected_repro_sha

    att = json.loads(att_path.read_text())
    assert att["schema_version"] == 1
    assert att["kind"] == "vantix.report_attestation.v1"
    names = {entry["path"] for entry in att["reports"]}
    # markdown + html + provenance all covered.
    assert "run_report.md" in names
    assert "run_report.html" in names
    assert "findings.provenance.json" in names
    # Each listed sha256 must match the file's current digest.
    for entry in att["reports"]:
        target = prov_path.parent / entry["path"]
        assert target.is_file()
        assert hashlib.sha256(target.read_bytes()).hexdigest() == entry["sha256"]
        assert entry["size_bytes"] == target.stat().st_size
