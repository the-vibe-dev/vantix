from __future__ import annotations

import json
from pathlib import Path

from secops.services.benchmarks import BenchmarkCatalog


def _write_benchmark(root: Path, benchmark_id: str = "BENCH-001") -> None:
    bench_dir = root / "benchmarks" / benchmark_id
    bench_dir.mkdir(parents=True)
    (bench_dir / "benchmark.json").write_text(
        json.dumps(
            {
                "name": "Fixture benchmark",
                "description": "Self-contained unit-test fixture.",
                "level": "easy",
                "tags": ["fixture", "web"],
                "win_condition": "service responds",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (bench_dir / "docker-compose.yml").write_text(
        """
services:
  fixture_app:
    image: nginx:alpine
    ports:
      - "8080:80"
""".lstrip(),
        encoding="utf-8",
    )


def test_benchmark_catalog_reads_local_fixture(tmp_path: Path) -> None:
    _write_benchmark(tmp_path)

    records = BenchmarkCatalog(root=tmp_path).list_benchmarks()

    assert len(records) == 1
    assert records[0].benchmark_id == "BENCH-001"
    assert records[0].tags == ["fixture", "web"]


def test_benchmark_compose_services_parse_local_fixture(tmp_path: Path) -> None:
    _write_benchmark(tmp_path)

    services = BenchmarkCatalog(root=tmp_path).compose_services("BENCH-001")

    assert "fixture_app" in services
    assert services["fixture_app"]["ports"] == ["8080:80"]
