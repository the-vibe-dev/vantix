"""P2-4 — reporter renders custody trio, evidence_ids links, and reproduction script."""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_reporting_custody_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

from secops.db import Base, SessionLocal, engine
from secops.models import Engagement, Finding, User, WorkspaceRun
from secops.services.reporting import ReportingService


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _seed_run_and_finding(db) -> WorkspaceRun:
    eng = Engagement(name="Custody Report", mode="pentest", target="10.0.0.1", tags=["pentest"])
    db.add(eng)
    db.flush()
    run = WorkspaceRun(
        engagement_id=eng.id,
        mode="pentest",
        workspace_id=f"ws-{eng.id[:8]}",
        status="running",
        objective="custody reporting",
        target="10.0.0.1",
        config_json={},
    )
    user = User(id="user-alice", username="alice", password_hash="x", role="operator")
    db.add_all([run, user])
    db.flush()
    finding = Finding(
        run_id=run.id,
        title="Reflected XSS on /search",
        severity="high",
        status="validated",
        summary="Query parameter echoed unescaped",
        evidence="<script>alert(1)</script> appears in body",
        reproduction="Visit /search?q=<script>alert(1)</script>",
        remediation="Encode output using context-aware escaping",
        confidence=0.85,
        fingerprint="fp-xss-custody",
        evidence_ids=["art-screenshot-123", "art-proof-456"],
        reproduction_script="curl -sS 'https://target/search?q=%3Cscript%3E'",
        promoted_at=datetime(2026, 4, 21, 12, 0, 0, tzinfo=timezone.utc),
        reviewed_at=datetime(2026, 4, 21, 13, 15, 0, tzinfo=timezone.utc),
        reviewer_user_id="user-alice",
        disposition="confirmed",
    )
    db.add(finding)
    db.flush()
    return run


def test_markdown_report_renders_custody_trio_and_evidence_links(tmp_path: Path) -> None:
    _reset_db()
    with SessionLocal() as db:
        run = _seed_run_and_finding(db)
        db.commit()
        service = ReportingService()
        outputs = service.generate(db, run)
        md_path = Path(outputs["markdown_path"])
        assert md_path.exists()
        text = md_path.read_text(encoding="utf-8")

    # Custody trio rendered.
    assert "Disposition: confirmed" in text
    assert "Promoted: 2026-04-21" in text
    assert "Reviewed: 2026-04-21" in text
    assert "by user user-alice" in text

    # Reproduction script rendered as a fenced code block.
    assert "**Reproduction Script**" in text
    assert "```bash" in text
    assert "curl -sS 'https://target/search?q=%3Cscript%3E'" in text

    # Evidence IDs rendered as markdown links.
    assert "**Linked Evidence**" in text
    assert "[art-screenshot-123](artifacts/art-screenshot-123)" in text
    assert "[art-proof-456](artifacts/art-proof-456)" in text
