"""PRA-016: manifest verifier refuses to accept corrupted payloads."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secops.release_verify import VerificationError, verify_manifest


def _build_tree(root: Path) -> dict[str, bytes]:
    files = {
        "secops/app.py": b"print('ok')\n",
        "alembic/env.py": b"# env\n",
        "docs/operations/database.md": b"# db\n",
    }
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return files


def _manifest_for(root: Path, files: dict[str, bytes]) -> dict:
    return {
        "version": "v0.0.0-test",
        "git_sha": "deadbeef",
        "package": root.name,
        "files": [
            {
                "path": rel,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for rel, content in files.items()
        ],
    }


def test_verify_manifest_happy_path(tmp_path: Path) -> None:
    pkg = tmp_path / "vantix-test"
    files = _build_tree(pkg)
    manifest = _manifest_for(pkg, files)
    # When extracted_root is tmp_path, package directory is tmp_path / package.
    verify_manifest(tmp_path, manifest)


def test_verify_manifest_detects_tampered_file(tmp_path: Path) -> None:
    pkg = tmp_path / "vantix-test"
    files = _build_tree(pkg)
    manifest = _manifest_for(pkg, files)
    # Tamper with one file after manifest generation
    (pkg / "secops/app.py").write_bytes(b"print('HAXX')\n")
    with pytest.raises(VerificationError, match="sha256 mismatch"):
        verify_manifest(tmp_path, manifest)


def test_verify_manifest_missing_file(tmp_path: Path) -> None:
    pkg = tmp_path / "vantix-test"
    files = _build_tree(pkg)
    manifest = _manifest_for(pkg, files)
    (pkg / "alembic/env.py").unlink()
    with pytest.raises(VerificationError, match="missing on disk"):
        verify_manifest(tmp_path, manifest)


def test_verify_manifest_rejects_empty(tmp_path: Path) -> None:
    with pytest.raises(VerificationError, match="declares no files"):
        verify_manifest(tmp_path, {"files": []})


def test_release_fingerprint_guard(tmp_path: Path, monkeypatch) -> None:
    from secops.services.installer_state import InstallerStateService

    svc = InstallerStateService(runtime_root=tmp_path)

    # First boot records the fingerprint.
    first = svc.verify_release_integrity(
        current_git_sha="aaaa1111",
        current_manifest_sha256="m1",
    )
    assert first["ok"] is True

    # Matching subsequent boot is ok.
    match = svc.verify_release_integrity(
        current_git_sha="aaaa1111",
        current_manifest_sha256="m1",
    )
    assert match["ok"] is True

    # Mismatch without the ack env refuses.
    monkeypatch.delenv("VANTIX_ACCEPT_VERSION_CHANGE", raising=False)
    rejected = svc.verify_release_integrity(
        current_git_sha="bbbb2222",
        current_manifest_sha256="m2",
    )
    assert rejected["ok"] is False
    assert "mismatch" in rejected["detail"]

    # Ack env with the new sha unlocks the change.
    monkeypatch.setenv("VANTIX_ACCEPT_VERSION_CHANGE", "bbbb2222")
    accepted = svc.verify_release_integrity(
        current_git_sha="bbbb2222",
        current_manifest_sha256="m2",
    )
    assert accepted["ok"] is True
