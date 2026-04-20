# Workflow Engine

## Purpose

`secops/services/workflows/engine.py` provides durable, DB-backed orchestration for run phases.

## Core Records

- `WorkflowExecution`: run-level orchestration state
- `WorkflowPhaseRun`: phase attempt state
- `WorkerLease`: claim/heartbeat/expiry for workers
- `RunCheckpoint`: phase checkpoints for continuity
- `RunMetric`: structured telemetry

## Execution Lifecycle

1. Run is enqueued.
2. Worker claims next runnable phase.
3. Phase handler executes under policy controls.
4. Outcome is persisted as `completed`, `blocked`, `retry`, or `failed`.
5. Engine advances next phase or closes workflow.

## Phase Model

Current phase flow includes:

- `context-bootstrap`
- `learning-recall`
- `recon-sidecar`
- `browser-assessment`
- `cve-analysis`
- `orchestrate`
- `learn-ingest`
- `report`

## Recovery and Idempotency

- Expired leases are reclaimable.
- Stale claims are scavenged back into runnable state and surfaced through workflow metrics.
- Retry classification normalizes transient vs permanent failures.
- Resume/restart behavior is driven by persisted workflow state, not in-memory loops.

## Operator Impact

Workflow state drives:

- engagement phase visualization
- specialist status
- approval-required blockers
- report generation readiness
