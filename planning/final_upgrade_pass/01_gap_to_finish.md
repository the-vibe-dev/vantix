# Gap To Finish

## Priority Gaps (Ranked)

1. **Atomic claim + lease ownership safety** (highest impact, high risk if unfixed)
   - Prevent duplicate workers claiming/finishing same phase attempt.

2. **Lease renewal heartbeat while phase executes** (highest impact)
   - Prevent stale-lease reclaim during long phase handlers.

3. **Completion/failure idempotency guards + transition metrics** (high impact)
   - Enforce state transition integrity and emit `RunMetric` counters/durations.

4. **Policy enforcement expansion + audit trail** (high impact)
   - Cover high-noise recon/exploit validation/write/network classes.
   - Persist structured policy decision events.

5. **Workflow API contract + frontend wiring** (medium-high impact)
   - Add workflow-state endpoint for attempts/retries/lease diagnostics.
   - Update UI panels to show durable workflow details clearly.

6. **Bug and hygiene fixes** (medium impact)
   - Remove duplicate vector-selection replan call.
   - Ensure no obvious secret/operator leakage in checked-in docs/examples.

7. **Test hardening for new runtime guarantees** (high impact)
   - Add focused tests for atomic claims, lease renewals, workflow endpoint, policy audit.
