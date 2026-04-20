# Upgrade Notes

## Scope

This upgrade introduces durable workflow orchestration, worker lease tracking, explicit retries, policy-gated execution, improved planning intelligence, and deterministic report outputs.

## Compatibility

- `/api/v1/chat` behavior is preserved.
- Existing run/vector/attack-chain/approval/handoff flows remain available.
- New response fields are additive (`report_json_path`, worker status, planning bundle endpoint).

## Schema Additions

New tables (auto-created by metadata at startup):

- `workflow_executions`
- `workflow_phase_runs`
- `run_checkpoints`
- `worker_leases`
- `run_metrics`

## Operational Notes

- Worker runtime starts when a run is queued.
- If codex/script execution is disabled or blocked by policy, runs enter blocked state with approvals/events.
- Retryable failures create new phase attempts.
