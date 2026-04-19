#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import yaml


HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443}


def parse_port_entry(entry: Any) -> tuple[int, str]:
    if isinstance(entry, int):
        return entry, "tcp"
    if isinstance(entry, str):
        raw = entry
        if "/" in raw:
            raw, proto = raw.rsplit("/", 1)
        else:
            proto = "tcp"
        tail = raw.rsplit(":", 1)[-1]
        if tail.isdigit():
            return int(tail), proto
    raise ValueError(f"Unsupported port entry: {entry!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic LAN port map and compose override files.")
    parser.add_argument("--bench-root", default="./tools/validation-benchmarks/benchmarks")
    parser.add_argument("--out-dir", default="./artifacts/benchmarks/devwork_lan_map")
    parser.add_argument("--lan-host", default="127.0.0.1")
    parser.add_argument("--base-port", type=int, default=32001)
    args = parser.parse_args()

    bench_root = Path(args.bench_root)
    out_dir = Path(args.out_dir)
    overrides_dir = out_dir / "overrides"
    composes_dir = out_dir / "composes"
    out_dir.mkdir(parents=True, exist_ok=True)
    overrides_dir.mkdir(parents=True, exist_ok=True)
    composes_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    bundles: list[dict[str, Any]] = []
    next_port = args.base_port

    for bench_dir in sorted(bench_root.glob("XBEN-*")):
        compose_path = bench_dir / "docker-compose.yml"
        if not compose_path.exists():
            continue

        data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        services = data.get("services", {}) or {}
        override_services: dict[str, dict[str, list[str]]] = {}
        rendered = dict(data)
        rendered_services = dict(services)
        endpoints: list[dict[str, Any]] = []

        for service_name, service_cfg in services.items():
            ports = service_cfg.get("ports", []) or []
            if not ports:
                continue
            override_ports: list[str] = []
            for port_entry in ports:
                container_port, proto = parse_port_entry(port_entry)
                host_port = next_port
                next_port += 1
                url = (
                    f"http://{args.lan_host}:{host_port}"
                    if container_port in HTTP_PORTS
                    else f"{args.lan_host}:{host_port}"
                )
                endpoints.append(
                    {
                        "service": service_name,
                        "container_port": container_port,
                        "proto": proto,
                        "host_port": host_port,
                        "url": url,
                    }
                )
                rows.append(
                    {
                        "benchmark_id": bench_dir.name,
                        "service": service_name,
                        "container_port": container_port,
                        "proto": proto,
                        "host_port": host_port,
                        "url": url,
                        "status": "planned",
                    }
                )
                override_ports.append(f"{host_port}:{container_port}/{proto}")

            override_services[service_name] = {"ports": override_ports}
            service_copy = dict(service_cfg)
            service_copy["ports"] = override_ports
            rendered_services[service_name] = service_copy

        override = {"services": override_services}
        (overrides_dir / f"{bench_dir.name}.override.yml").write_text(
            yaml.safe_dump(override, sort_keys=False),
            encoding="utf-8",
        )
        rendered["services"] = rendered_services
        (composes_dir / f"{bench_dir.name}.compose.yml").write_text(
            yaml.safe_dump(rendered, sort_keys=False),
            encoding="utf-8",
        )

        bundles.append(
            {
                "benchmark_id": bench_dir.name,
                "status": "planned",
                "endpoint_count": len(endpoints),
                "endpoints": endpoints,
            }
        )

    (out_dir / "benchmarks.json").write_text(json.dumps(bundles, indent=2), encoding="utf-8")
    (out_dir / "endpoints.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    with (out_dir / "endpoints.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["benchmark_id", "service", "container_port", "proto", "host_port", "url", "status"],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(bundles)} benchmark bundles")
    print(f"Assigned {len(rows)} endpoint mappings")
    print(f"Output: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
