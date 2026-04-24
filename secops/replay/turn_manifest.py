"""V2-12 — Real replay manifest derived from the agent message bus.

Prior ``secops.replay.manifest.build_replay_manifest`` summarises a run
from ``run_events`` / ``artifacts``. That's useful for the UI but it is
not byte-for-byte reproducible. This module builds a canonical per-turn
manifest from ``bus_events`` so a verifier can:

1. Replay the run by re-feeding each turn's plan/actions/observations
   into the planner loop.
2. Recompute ``msg_sha256`` for each envelope and compare against the
   signed manifest.
3. Trace ``parent_turn_id`` back to a base run for branched runs
   (V2-13 ``branch_from_step``).

The manifest is stable JSON (sorted keys, tight separators) so cosign
signatures cover a deterministic byte stream.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from secops.models import BusEvent, WorkspaceRun


REPLAY_TURN_SCHEMA_VERSION = "vantix.replay.v2"


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _envelope_sha256(event: BusEvent) -> str:
    # Deterministic hash over the wire envelope: include routing fields
    # and payload so a verifier can reconstruct the BusEnvelope bytes.
    wire = {
        "run_id": event.run_id,
        "branch_id": event.branch_id,
        "seq": int(event.seq),
        "turn_id": int(event.turn_id),
        "agent": event.agent,
        "type": event.type,
        "payload": event.payload_json or {},
        "parent_turn_id": event.parent_turn_id,
        "caused_by_fact_ids": list(event.caused_by_fact_ids or []),
    }
    return hashlib.sha256(_canonical_bytes(wire)).hexdigest()


@dataclass(frozen=True)
class TurnEntry:
    turn_id: int
    agent: str
    type: str
    seq: int
    msg_sha256: str
    parent_turn_id: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "turn_id": self.turn_id,
            "agent": self.agent,
            "type": self.type,
            "seq": self.seq,
            "msg_sha256": self.msg_sha256,
            "parent_turn_id": self.parent_turn_id,
        }


def build_turn_manifest(
    db: Session,
    run: WorkspaceRun,
    *,
    branch_id: str = "main",
) -> dict[str, Any]:
    """Return a canonical per-turn manifest for ``(run, branch)``.

    Every bus event becomes one ``turns[]`` entry so replay covers plan,
    action, observation, critique, and policy_decision messages.
    """
    rows = (
        db.query(BusEvent)
        .filter(BusEvent.run_id == run.id)
        .filter(BusEvent.branch_id == branch_id)
        .order_by(BusEvent.seq.asc())
        .all()
    )
    turns: list[dict[str, Any]] = []
    for ev in rows:
        turns.append(
            TurnEntry(
                turn_id=int(ev.turn_id),
                agent=str(ev.agent),
                type=str(ev.type),
                seq=int(ev.seq),
                msg_sha256=_envelope_sha256(ev),
                parent_turn_id=ev.parent_turn_id,
            ).as_dict()
        )

    chain_sha256 = hashlib.sha256(
        b"\n".join(t["msg_sha256"].encode("ascii") for t in turns)
    ).hexdigest() if turns else hashlib.sha256(b"").hexdigest()

    return {
        "schema_version": REPLAY_TURN_SCHEMA_VERSION,
        "kind": "vantix.replay.v2",
        "run_id": run.id,
        "branch_id": branch_id,
        "base_run_id": run.resumed_from_run_id or None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "turn_count": len(turns),
        "chain_sha256": chain_sha256,
        "turns": turns,
    }


def write_turn_manifest(
    db: Session,
    run: WorkspaceRun,
    out_path: Path,
    *,
    branch_id: str = "main",
) -> Path:
    """Write the manifest as canonical JSON bytes and return the path."""
    manifest = build_turn_manifest(db, run, branch_id=branch_id)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Pretty-print for human diff but keep sorted keys for determinism.
    out_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return out_path


def sign_turn_manifest(manifest_path: Path, *, script: Path | None = None) -> tuple[Path, Path]:
    """Run ``scripts/sign-report.sh`` on the manifest, returning (sig, cert)."""
    script_path = script or Path(__file__).resolve().parents[2] / "scripts" / "sign-report.sh"
    if not script_path.is_file():
        raise FileNotFoundError(f"sign-report.sh not found at {script_path}")
    subprocess.run([str(script_path), str(manifest_path)], check=True)
    return manifest_path.with_suffix(manifest_path.suffix + ".sig"), manifest_path.with_suffix(manifest_path.suffix + ".pem")


__all__ = [
    "REPLAY_TURN_SCHEMA_VERSION",
    "TurnEntry",
    "build_turn_manifest",
    "write_turn_manifest",
    "sign_turn_manifest",
]
