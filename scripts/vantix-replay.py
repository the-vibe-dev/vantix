#!/usr/bin/env python3
"""V25-07 — vantix-replay CLI.

Usage:
    vantix-replay <spec-id> [--json] [--quiet]

Exits 0 on a clean replay (zero divergences), non-zero on any divergence
or runtime error. Stdout summarises the replay run; with ``--json`` the
output is a single JSON object suitable for piping into CI tooling.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _format_summary(outcome) -> str:
    lines = [
        f"replay_run_id: {outcome.replay_run_id}",
        f"spec_id:       {outcome.spec_id}",
        f"status:        {outcome.status}",
        f"divergences:   {outcome.divergence_count}",
        f"steps:         {len(outcome.steps)}",
    ]
    diverged = [s for s in outcome.steps if s.diverged]
    if diverged:
        lines.append("")
        lines.append("Divergent turns:")
        for s in diverged:
            lines.append(
                f"  turn={s.turn_id:<4} seq={s.seq:<4} agent={s.agent:<10} "
                f"type={s.type:<14} kind={s.divergence_kind}"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay a Vantix run from a signed turn manifest.")
    parser.add_argument("spec_id", help="ReplaySpec id to execute.")
    parser.add_argument("--json", action="store_true", help="Emit a single JSON object.")
    parser.add_argument("--quiet", action="store_true", help="Suppress the human summary on success.")
    args = parser.parse_args(argv)

    from secops.db import SessionLocal
    from secops.replay.engine import replay

    try:
        with SessionLocal() as db:
            outcome = replay(db, args.spec_id)
            db.commit()
    except ValueError as exc:
        sys.stderr.write(f"vantix-replay: {exc}\n")
        return 2
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"vantix-replay: error: {exc}\n")
        return 3

    if args.json:
        payload = {
            "replay_run_id": outcome.replay_run_id,
            "spec_id": outcome.spec_id,
            "status": outcome.status,
            "divergence_count": outcome.divergence_count,
            "steps": [
                {
                    "turn_id": s.turn_id,
                    "seq": s.seq,
                    "agent": s.agent,
                    "type": s.type,
                    "expected_sha256": s.expected_sha256,
                    "actual_sha256": s.actual_sha256,
                    "divergence_kind": s.divergence_kind,
                }
                for s in outcome.steps
            ],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    elif not args.quiet or outcome.divergence_count:
        sys.stdout.write(_format_summary(outcome) + "\n")

    return 0 if outcome.divergence_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
