# Worker Runtime

## Module

`secops/services/worker_runtime.py`

## Responsibilities

- run claim loop for phase attempts
- execute one phase at a time
- mark completed/blocked/failed/retry outcomes
- expose worker snapshot for `/api/v1/system/status`

## Snapshot Fields

- `worker_id`
- `running`
- `heartbeat_at`
- `claimed_run_id`
- `claimed_phase`
- `lease_expires_at`

## Local Compatibility

The default runtime is single-host and starts on first queued run. It is designed to preserve current local operator workflows.
