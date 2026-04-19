from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from secops.config import settings


@dataclass(frozen=True)
class BenchmarkRecord:
    benchmark_id: str
    path: Path
    name: str
    description: str
    level: str
    tags: list[str]
    win_condition: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "path": str(self.path),
            "name": self.name,
            "description": self.description,
            "level": self.level,
            "tags": self.tags,
            "win_condition": self.win_condition,
        }


class BenchmarkCatalog:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or settings.validation_benchmarks_root).resolve()
        self.benchmarks_root = self.root / "benchmarks"

    def list_benchmarks(self) -> list[BenchmarkRecord]:
        if not self.benchmarks_root.exists():
            return []
        records = []
        for bench_dir in sorted(self.benchmarks_root.iterdir()):
            if not bench_dir.is_dir():
                continue
            metadata = self._load_metadata(bench_dir)
            if metadata is None:
                continue
            records.append(metadata)
        return records

    def get(self, benchmark_id: str) -> BenchmarkRecord:
        bench_dir = self.benchmarks_root / benchmark_id
        metadata = self._load_metadata(bench_dir)
        if metadata is None:
            raise FileNotFoundError(f"Unknown benchmark: {benchmark_id}")
        return metadata

    def compose_services(self, benchmark_id: str) -> dict[str, Any]:
        bench_dir = self.benchmarks_root / benchmark_id
        compose_path = bench_dir / "docker-compose.yml"
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
        return data.get("services", {})

    def launch(self, benchmark_id: str) -> dict[str, Any]:
        record = self.get(benchmark_id)
        build_cmd = ["sudo", "make", "-C", str(record.path), "build"]
        build = subprocess.run(build_cmd, capture_output=True, text=True, check=False)
        if build.returncode == 0:
            up_cmd = [
                "sudo",
                "docker",
                "compose",
                "-f",
                str(record.path / "docker-compose.yml"),
                "up",
                "-d",
            ]
            result = subprocess.run(up_cmd, capture_output=True, text=True, check=False, cwd=record.path)
        else:
            result = build
        endpoints = self.resolve_endpoints(benchmark_id)
        return {
            "benchmark": record.to_dict(),
            "returncode": result.returncode,
            "stdout": "\n".join(part for part in [build.stdout, result.stdout] if part),
            "stderr": "\n".join(part for part in [build.stderr, result.stderr] if part),
            "endpoints": endpoints,
        }

    def stop(self, benchmark_id: str) -> dict[str, Any]:
        record = self.get(benchmark_id)
        command = [
            "sudo",
            "docker",
            "compose",
            "-f",
            str(record.path / "docker-compose.yml"),
            "stop",
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False, cwd=record.path)
        return {
            "benchmark": record.to_dict(),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def resolve_endpoints(self, benchmark_id: str) -> list[dict[str, Any]]:
        services = self.compose_services(benchmark_id)
        endpoints: list[dict[str, Any]] = []
        for service_name, service_cfg in services.items():
            if "ports" not in service_cfg:
                continue
            for entry in service_cfg.get("ports", []):
                container_port = self._container_port(entry)
                if container_port is None:
                    continue
                port_cmd = [
                    "sudo",
                    "docker",
                    "compose",
                    "-f",
                    str(self.benchmarks_root / benchmark_id / "docker-compose.yml"),
                    "port",
                    service_name,
                    str(container_port),
                ]
                result = subprocess.run(port_cmd, capture_output=True, text=True, check=False, cwd=self.benchmarks_root / benchmark_id)
                host_port = self._parse_compose_port(result.stdout.strip())
                if host_port is None:
                    continue
                scheme = "http" if container_port in {80, 3000, 5000, 8000, 8080} else "tcp"
                url = f"{scheme}://127.0.0.1:{host_port}"
                endpoints.append(
                    {
                        "service": service_name,
                        "container_port": container_port,
                        "host_port": host_port,
                        "url": url,
                    }
                )
        return endpoints

    def _load_metadata(self, bench_dir: Path) -> BenchmarkRecord | None:
        if not bench_dir.exists():
            return None
        metadata_path = bench_dir / "benchmark.json"
        if not metadata_path.exists():
            return None
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        return BenchmarkRecord(
            benchmark_id=bench_dir.name,
            path=bench_dir,
            name=payload.get("name", bench_dir.name),
            description=payload.get("description", ""),
            level=str(payload.get("level", "")),
            tags=list(payload.get("tags", [])),
            win_condition=payload.get("win_condition", ""),
        )

    def _container_port(self, entry: Any) -> int | None:
        if isinstance(entry, int):
            return entry
        if isinstance(entry, str):
            tail = entry.split(":")[-1]
            tail = tail.split("/")[0]
            if tail.isdigit():
                return int(tail)
        return None

    def _parse_compose_port(self, output: str) -> int | None:
        if not output:
            return None
        _, _, port = output.rpartition(":")
        return int(port) if port.isdigit() else None
