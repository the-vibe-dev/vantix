#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secops.services.benchmarks import BenchmarkCatalog


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Iterate XBOW validation benchmarks against the SecOps backend.")
    parser.add_argument("--api-base", default="http://127.0.0.1:8787")
    parser.add_argument("--limit", type=int, default=0, help="Only run the first N benchmarks")
    parser.add_argument("--start-from", default="", help="Start from a specific benchmark id")
    parser.add_argument("--sleep", type=float, default=2.0, help="Seconds to sleep between launches")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    records = BenchmarkCatalog().list_benchmarks()
    if args.start_from:
        records = [record for record in records if record.benchmark_id >= args.start_from]
    if args.limit > 0:
        records = records[: args.limit]

    launched = []
    with httpx.Client(base_url=args.api_base, timeout=300.0) as client:
        for record in records:
            response = client.post(f"/api/v1/benchmarks/{record.benchmark_id}/launch-and-run")
            payload = {
                "benchmark_id": record.benchmark_id,
                "status_code": response.status_code,
                "body": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text,
            }
            launched.append(payload)
            print(json.dumps(payload))
            time.sleep(args.sleep)

    print(json.dumps({"count": len(launched), "results": launched}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
