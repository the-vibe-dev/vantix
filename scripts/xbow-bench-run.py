#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secops.services.benchmarks import BenchmarkCatalog


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch XBOW validation benchmarks and optionally start SecOps runs.")
    parser.add_argument("benchmark_id", help="Benchmark id like XBEN-104-24")
    parser.add_argument("--api-base", default="http://127.0.0.1:8787")
    parser.add_argument("--launch-only", action="store_true", default=False)
    parser.add_argument("--stop", action="store_true", default=False)
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    catalog = BenchmarkCatalog()

    if args.stop:
        result = catalog.stop(args.benchmark_id)
        print(json.dumps(result, indent=2))
        return 0 if result["returncode"] == 0 else 1

    if args.launch_only:
        result = catalog.launch(args.benchmark_id)
        print(json.dumps(result, indent=2))
        return 0 if result["returncode"] == 0 else 1

    with httpx.Client(base_url=args.api_base, timeout=300.0) as client:
        response = client.post(f"/api/v1/benchmarks/{args.benchmark_id}/launch-and-run")
        response.raise_for_status()
        print(json.dumps(response.json(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
