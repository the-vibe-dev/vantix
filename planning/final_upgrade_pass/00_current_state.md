# Current State

## What Is Already Landed

- Durable workflow models exist in `secops/models.py`:
  - `WorkflowExecution`, `WorkflowPhaseRun`, `RunCheckpoint`, `WorkerLease`, `RunMetric`.
- DB-backed workflow engine exists in `secops/services/workflows/engine.py`:
  - enqueue, claim, complete, block, fail, retry scheduling, cancel/block transitions.
- Separate worker runtime loop exists in `secops/services/worker_runtime.py`.
- Execution policy and subprocess wrapper exist in `secops/services/policies.py`.
- Deterministic reporting service exists in `secops/services/reporting.py`.
- Frontend already surfaces worker and planning bundle basics in `frontend/src/App.tsx`.
- Docs and quality gates are present (`ruff`/`mypy`/`bandit` staged usage, workflow docs).

## Fragile / Incomplete Areas

1. Claim safety is still optimistic:
   - `claim_next_phase` loads then mutates a candidate without atomic claim guard.
2. Lease heartbeat/renewal:
   - No active lease renew while a phase is running; long phases can be reclaimed.
3. Completion idempotency under contention:
   - `mark_phase_completed` has no worker/lease ownership guard.
4. Workflow metrics are modeled but not emitted in runtime transitions.
5. Policy coverage is narrow:
   - only `script`/`codex` action kinds are evaluated.
   - policy decisions are not centrally audited as structured events.
6. Retry classifier is simplistic and exception mapping is weak.
7. API contract lacks first-class workflow state payload for UI:
   - UI still depends on legacy `phase_state` and ad hoc data pulls.
8. Bug observed:
   - duplicate `VantixScheduler().replan(...)` call in vector select endpoint.
9. Tests missing coverage for:
   - lease renewal behavior
   - claim race protection
   - workflow status endpoint contract
   - policy audit event behavior.
