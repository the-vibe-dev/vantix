# Architecture

## Control Plane

- API routers: `secops/routers/*`.
- Chat entrypoint: `/api/v1/chat` (preserved contract).
- Scheduler: `secops/services/vantix.py` seeds tasks, roles, vectors, and notes.
- System status: `secops/routers/system.py` includes runtime, tooling, and worker state.

## Durable Workflow Layer

- Engine: `secops/services/workflows/engine.py`.
- Phase sequence metadata: `secops/services/workflows/phases.py`.
- Retry classifier: `secops/services/workflows/retries.py`.
- Checkpoint handling: `secops/services/workflows/checkpoints.py`.
- DB entities in `secops/models.py`:
  - `WorkflowExecution`
  - `WorkflowPhaseRun`
  - `RunCheckpoint`
  - `WorkerLease`
  - `RunMetric`

The API enqueues work. Worker runtime claims phase attempts from DB and executes them with lease records.

## Worker Runtime

- Module: `secops/services/worker_runtime.py`.
- Single-host compatibility worker thread exists by default.
- Worker claims a phase, executes it, and writes completion/retry/blocked/failure updates.
- Stale lease recovery is supported by claim logic on expired leases.

## Execution And Safety Adapters

- Dispatcher/compat layer: `secops/services/execution.py`.
- Execution policies + subprocess hardening: `secops/services/policies.py`.
- Reporting synthesis: `secops/services/reporting.py`.

## Product Strengths Preserved

- vectors and attack chains
- approvals and handoffs
- skill packs and operator notes
- user-owned runtime storage
- chat-first operator flow

## Storage Model

Runtime data remains user-owned under local state roots (`StorageLayout`) and includes prompts, artifacts, reports, logs, handoffs, and memory files.

## Compatibility Note

Internal package naming remains `secops` for compatibility. Product-facing behavior remains Vantix.
