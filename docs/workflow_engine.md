# Workflow Engine

## Purpose

`secops/services/workflows/engine.py` provides durable orchestration state and DB-backed phase claim progression.

## Core Records

- `WorkflowExecution`: run-level workflow state.
- `WorkflowPhaseRun`: attempt-level phase state.
- `WorkerLease`: claim/heartbeat/expiry state.
- `RunMetric`: per-run/per-phase telemetry entries.

## Lifecycle

1. enqueue run (`ExecutionManager.start` -> `WorkflowEngine.enqueue_run`)
2. worker claims next pending phase
3. phase executes
4. phase is marked completed, blocked, failed, or retry-scheduled
5. next phase becomes pending or workflow ends

## Recovery

- stale claimed rows are reclaimable when lease expires.
- run can be resumed by re-enqueueing workflow state.
