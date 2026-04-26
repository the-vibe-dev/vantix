from __future__ import annotations

import hashlib
from pathlib import Path

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome


class ArtifactVerifier(ReplayVerifier):
    """File-based verifier: asserts an artifact exists and (optionally) contains a substring or matches a sha256.

    Replay payload schema:
        path: str (required) — absolute or workspace-relative
        contains: str (optional) — UTF-8 substring that must appear in the file
        sha256: str (optional) — expected hex digest of the file bytes
        max_bytes: int (default 4MB) — read cap for ``contains`` checks
    """

    type = "artifact"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        payload = spec.payload
        raw_path = str(payload.get("path") or "").strip()
        if not raw_path:
            return VerifyOutcome(validated=False, reason="replay.path missing")
        candidate = Path(raw_path)
        if not candidate.is_absolute() and ctx.workspace_root is not None:
            candidate = Path(ctx.workspace_root) / candidate
        if not candidate.is_file():
            return VerifyOutcome(validated=False, reason=f"artifact missing: {candidate}")

        max_bytes = int(payload.get("max_bytes") or (4 * 1024 * 1024))
        try:
            data = candidate.read_bytes()[:max_bytes]
        except OSError as exc:
            return VerifyOutcome(validated=False, reason=f"artifact read failed: {exc}")

        signal = {
            "path": str(candidate),
            "size": candidate.stat().st_size,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        failed: list[str] = []
        expected_sha = str(payload.get("sha256") or "").strip().lower()
        if expected_sha and expected_sha != signal["sha256"]:
            failed.append("sha256 mismatch")
        contains = payload.get("contains")
        if contains:
            text = data.decode("utf-8", errors="replace")
            if str(contains) not in text:
                failed.append("contains not matched")

        if failed:
            return VerifyOutcome(validated=False, reason="; ".join(failed), signal=signal)
        return VerifyOutcome(validated=True, signal=signal)
