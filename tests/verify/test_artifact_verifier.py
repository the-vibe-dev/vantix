from __future__ import annotations

import hashlib

from secops.verify import ReplaySpec, VerifyContext
from secops.verify.artifact import ArtifactVerifier


def test_artifact_missing_path(tmp_path):
    out = ArtifactVerifier().verify(ReplaySpec(type="artifact", payload={}), VerifyContext())
    assert out.validated is False
    assert "missing" in out.reason


def test_artifact_happy_path_with_contains(tmp_path):
    target = tmp_path / "proof.txt"
    target.write_text("the canary phrase appears here", encoding="utf-8")
    out = ArtifactVerifier().verify(
        ReplaySpec(type="artifact", payload={"path": str(target), "contains": "canary phrase"}),
        VerifyContext(),
    )
    assert out.validated is True
    assert out.signal["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()


def test_artifact_sha256_mismatch(tmp_path):
    target = tmp_path / "proof.txt"
    target.write_text("contents", encoding="utf-8")
    out = ArtifactVerifier().verify(
        ReplaySpec(type="artifact", payload={"path": str(target), "sha256": "deadbeef"}),
        VerifyContext(),
    )
    assert out.validated is False
    assert "sha256 mismatch" in out.reason


def test_artifact_workspace_relative(tmp_path):
    sub = tmp_path / "evidence"
    sub.mkdir()
    target = sub / "p.txt"
    target.write_text("ok", encoding="utf-8")
    out = ArtifactVerifier().verify(
        ReplaySpec(type="artifact", payload={"path": "evidence/p.txt"}),
        VerifyContext(workspace_root=tmp_path),
    )
    assert out.validated is True
