# Risk Register

## R1: `/api/v1/chat` behavior regression

- Breakage potential:
  - New runs no longer auto-start or existing runs no longer replan.
- Mitigation:
  - Preserve current chat submit contract and response fields.
  - Keep `ExecutionManager.start()` entrypoint as compatibility façade.
- Rollback:
  - Revert routing of chat start to legacy execution path while retaining schema additions.

## R2: Duplicate writes during retry/resume

- Breakage potential:
  - Duplicate facts/artifacts/events on repeated phase attempts.
- Mitigation:
  - Idempotency checks keyed by `(run_id, phase_name)` checkpoint completeness + artifact existence.
  - Retry writes new attempt rows but reuses prior output where valid.
- Rollback:
  - Disable automatic retries and require manual retry while retaining checkpoint history.

## R3: Lease deadlocks or stale claims

- Breakage potential:
  - Runs stuck in claimed state with no active worker.
- Mitigation:
  - Lease heartbeat + expiration checks.
  - Recovery path to reclaim expired leases.
- Rollback:
  - Force-clear active leases via admin path and run fallback single-worker in-process mode.

## R4: Frontend/API contract drift

- Breakage potential:
  - UI errors from missing/renamed fields.
- Mitigation:
  - Additive API responses; preserve existing fields and add new workflow fields.
  - Update frontend in the same phase where response shape expands.
- Rollback:
  - Serve legacy shape adapters in schema serialization and gate UI usage with optional chaining.

## R5: Safety policy false positives

- Breakage potential:
  - Legitimate low-risk actions blocked unexpectedly.
- Mitigation:
  - Use explicit policy verdict classes and expose reasons in events/approvals.
  - Default to `allow_with_audit` for uncertain non-sensitive actions.
- Rollback:
  - Switch policy mode to permissive in config and retain audit events.

## R6: SQLite contention under worker loops

- Breakage potential:
  - Increased lock waits and slower throughput.
- Mitigation:
  - Keep transactions short in claim/heartbeat/update code.
  - Reuse existing WAL and timeout configuration from `secops/db.py`.
- Rollback:
  - Reduce worker polling cadence and run a single worker process until tuned.

## R7: Report overstatement / poor provenance

- Breakage potential:
  - Findings appear stronger than evidence.
- Mitigation:
  - Attach every report finding to fact/artifact/event references.
  - Include negative evidence section and explicit confidence.
- Rollback:
  - Limit report to factual timeline + artifacts while provenance mapping is refined.
