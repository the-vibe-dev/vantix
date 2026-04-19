#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from secops.services.memory_writer import DenseMemoryRecord, MemoryWriteService


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Write dense session memory")
    parser.add_argument("--root", default="")
    parser.add_argument("--mode", default="checkpoint")
    parser.add_argument("--session-id", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--agent", default="")
    parser.add_argument("--phase", default="")
    parser.add_argument("--objective", default="")
    parser.add_argument("--done", action="append", default=[])
    parser.add_argument("--issue", action="append", default=[])
    parser.add_argument("--next", default="")
    parser.add_argument("--file", action="append", default=[])
    parser.add_argument("--context", default="")
    parser.add_argument("--fact", action="append", default=[], help="kind=value")
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--latest", action="store_true")
    parser.add_argument("--stale-minutes", type=int, default=30)
    args = parser.parse_args()

    writer = MemoryWriteService(Path(args.root).resolve() if args.root else None)
    if args.health:
        print(json.dumps(writer.health(stale_minutes=args.stale_minutes), sort_keys=True))
        return 0
    if args.latest:
        print(json.dumps(writer.latest() or {}, sort_keys=True))
        return 0
    facts = []
    for raw in args.fact:
        if "=" in raw:
            k, v = raw.split("=", 1)
            facts.append([k, v])
    receipt = writer.write(
        DenseMemoryRecord(
            mode=args.mode,
            session_id=args.session_id,
            run_id=args.run_id,
            agent=args.agent,
            phase=args.phase,
            objective=args.objective,
            done=args.done,
            issues=args.issue,
            next_action=args.next,
            files=args.file,
            context=split_csv(args.context),
            facts=facts,
        )
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
