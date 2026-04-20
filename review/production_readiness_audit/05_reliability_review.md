# Reliability Review

## Runtime Model

- FastAPI (ASGI) process hosts the API *and* a daemon-threaded worker runtime (`worker_runtime.py`). Phases are claimed optimistically via UPDATE-with-rowcount on `workflow_phase_run`. Worker holds a `WorkerLease` with 90 s TTL renewed by a 20 s heartbeat.

## Correctness Risks

### Multi-worker split
- `worker_runtime.py` is a module-level singleton — N uvicorn workers = N claim loops. Optimistic locking makes duplicate claims rare but not impossible under Postgres without `FOR UPDATE SKIP LOCKED`. See PRA-007, PRA-020.

### Retry is a no-op
- `runs.py:retry_run` / `replan_run` only update `run.status`. See PRA-008.

### Session juggling
- `_phase_orchestrate` nests multiple SessionLocal blocks with mid-phase commits. Partial failure leaves inconsistent state. See PRA-019.

### Heartbeat vs lease TTL
- 20 s interval / 90 s TTL tolerates two missed heartbeats (good). Confirm: if worker process is SIGKILLed, next claimer waits up to 90 s before reclaim. Consider shortening TTL to 45 s with 10 s heartbeat for faster recovery.

### Graceful shutdown
- Daemon thread is abruptly terminated on process exit. Active leases remain until TTL. See PRA-042. Add lifespan shutdown hook: stop claim loop → mark leases `released`.

## Scalability Risks

- **Polling + SSE** both active — 2× fetch overhead. See PRA-021.
- **List endpoints unpaginated** — memory blowup on long runs. See PRA-027.
- **Terminal content concatenation** — O(events²) transfer. See PRA-022.
- **JSON blob columns** — no way to index on meaningful fields.

## Observability Gaps

- No metrics endpoint. No alerts possible.
- No structured logs. No request IDs.
- No `/readyz`.

## Data Integrity

- SQLite default is a single-writer store; contention beyond a handful of concurrent runs will serialize everything.
- No migrations → schema evolution is destructive.

## Failure Modes & Blast Radius

| Failure | Current Behavior | Desired |
|---|---|---|
| API crash mid-phase | Worker dies with it, lease stales for 90 s, no alert | Separate worker process; API restart independent |
| DB file corrupt | App won't start | Detect + surface clear error; backup/restore runbook |
| Subprocess hang | Subprocess never killed? (verify `timeout=` on subprocess calls) | Enforce per-action timeout in `run_subprocess` |
| Codex provider down | Phase likely marked failed; retry no-op (PRA-008) | Exponential backoff + dead-letter |
| Storage (`NAS`) unreachable | Writes fail, cascade unclear | Degrade to local fallback; alert |

## Recommendations (priority order)

1. Split worker into separate process; API becomes stateless.
2. Fix retry/replan.
3. Add `/readyz` + Prometheus metrics.
4. Enforce subprocess timeouts.
5. Paginate list endpoints + terminal deltas.
6. Postgres + Alembic before multi-tenant.
7. Lifespan shutdown hook.
