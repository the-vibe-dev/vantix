# Execution Order

1. **Workflow engine hardening**
   - atomic claim semantics
   - lease renewal method
   - completion/failed/blocked ownership guards
   - metric emission hooks

2. **Worker runtime hardening**
   - worker identity from env
   - per-claim heartbeat renewal loop
   - safer failure-path exception handling

3. **Execution/policy hardening**
   - central policy evaluation helper in execution manager
   - richer action kinds and structured policy audit events
   - retry classification improvements

4. **API contract improvements**
   - workflow status endpoint per run (attempts/lease/retry/block visibility)
   - remove duplicate vector replan call bug
   - additive schema response models

5. **Frontend contract tightening**
   - consume workflow status endpoint
   - show current owner worker, attempt count, retry/backoff, blocked reason

6. **Tests + checks**
   - workflow/lease/policy/API tests for new behavior
   - run backend tests + frontend build + check-all
