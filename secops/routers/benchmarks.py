from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.models import Engagement
from secops.schemas import RunControlResponse
from secops.security import require_api_token
from secops.services.benchmarks import BenchmarkCatalog
from secops.services.execution import execution_manager
from secops.services.run_service import RunService


router = APIRouter(prefix="/api/v1/benchmarks", tags=["benchmarks"], dependencies=[Depends(require_api_token)])


@router.get("")
def list_benchmarks() -> list[dict]:
    return [record.to_dict() for record in BenchmarkCatalog().list_benchmarks()]


@router.get("/{benchmark_id}")
def get_benchmark(benchmark_id: str) -> dict:
    try:
        record = BenchmarkCatalog().get(benchmark_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        **record.to_dict(),
        "endpoints": BenchmarkCatalog().resolve_endpoints(benchmark_id),
    }


@router.post("/{benchmark_id}/launch")
def launch_benchmark(benchmark_id: str) -> dict:
    try:
        return BenchmarkCatalog().launch(benchmark_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{benchmark_id}/stop")
def stop_benchmark(benchmark_id: str) -> dict:
    try:
        return BenchmarkCatalog().stop(benchmark_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{benchmark_id}/launch-and-run", response_model=RunControlResponse)
def launch_and_run_benchmark(benchmark_id: str, db: Session = Depends(get_db)) -> RunControlResponse:
    catalog = BenchmarkCatalog()
    try:
        launch = catalog.launch(benchmark_id)
        record = catalog.get(benchmark_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if launch["returncode"] != 0:
        raise HTTPException(status_code=500, detail=launch["stderr"] or "Benchmark launch failed")

    endpoints = launch["endpoints"]
    target = endpoints[0]["url"] if endpoints else ""

    eng = Engagement(
        name=record.name,
        mode="ctf",
        target=target,
        ruleset="validation-benchmark",
        status="active",
        notes=f"XBOW validation benchmark {benchmark_id}",
        tags=["ctf", "validation-benchmark", *record.tags],
        metadata_json={"benchmark_id": benchmark_id},
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)

    run = RunService(db).create_run(
        engagement_id=eng.id,
        objective=f"Solve benchmark {benchmark_id}: {record.name}",
        target=target,
        ports=[str(ep["host_port"]) for ep in endpoints],
        services=[ep["service"] for ep in endpoints],
        tags=["validation-benchmark", *record.tags],
        config={"benchmark_id": benchmark_id, "benchmark_endpoints": endpoints},
    )
    message = execution_manager.start(run.id)
    return RunControlResponse(run_id=run.id, status=run.status, message=message)
