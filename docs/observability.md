# Observability

## Persisted Signals

- run events (`run_events`)
- workflow execution/phase attempts
- worker leases and heartbeat
- run metrics
- report artifacts (`run_report.md`, `run_report.json`)

## API Surface

- `GET /api/v1/system/status` includes worker readiness and heartbeat.
- `GET /api/v1/runs/{run_id}/planning-bundle` exposes ranked vectors/chains and missing evidence.
- `GET /api/v1/runs/{run_id}/results` includes report paths.

## Event Hygiene

- blocked and approval conditions emit warning-level events.
- retries and failures are represented in phase attempts and workflow status.
