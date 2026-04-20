"""Release payload verification.

Two checks:
1. `verify_manifest(tarball, manifest)` walks the manifest and confirms each
   listed file's SHA-256 matches the extracted tree.
2. `verify_cosign(tarball, signature, certificate)` shells out to cosign to
   validate the GitHub-OIDC-issued signature.

Both are used by `scripts/install-vantix.sh` before unpacking into place.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManifestFile:
    path: str
    sha256: str
    size: int


def load_manifest(manifest_path: Path) -> dict:
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def verify_manifest(extracted_root: Path, manifest: dict) -> None:
    """Ensure every file declared by the manifest exists and its digest matches."""
    files = manifest.get("files") or []
    if not files:
        raise VerificationError("manifest declares no files")
    package = manifest.get("package", "")
    base = extracted_root / package if package and (extracted_root / package).exists() else extracted_root
    for entry in files:
        path = base / entry["path"]
        if not path.is_file():
            raise VerificationError(f"manifest file missing on disk: {entry['path']}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest.lower() != str(entry["sha256"]).lower():
            raise VerificationError(f"sha256 mismatch for {entry['path']}")


def verify_cosign(
    *,
    tarball: Path,
    signature: Path,
    certificate: Path,
    cert_identity_regexp: str,
    cert_oidc_issuer: str = "https://token.actions.githubusercontent.com",
) -> None:
    """Call cosign verify-blob. Raises VerificationError if cosign is missing or rejects the blob."""
    if shutil.which("cosign") is None:
        raise VerificationError(
            "cosign binary not found on PATH. Install from https://github.com/sigstore/cosign"
        )
    cmd = [
        "cosign",
        "verify-blob",
        "--certificate-identity-regexp",
        cert_identity_regexp,
        "--certificate-oidc-issuer",
        cert_oidc_issuer,
        "--signature",
        str(signature),
        "--certificate",
        str(certificate),
        str(tarball),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise VerificationError(
            f"cosign verify-blob failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )
