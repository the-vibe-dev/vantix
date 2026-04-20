# Test Gaps

## Current Coverage (inventory)

`tests/`:
- `test_api.py` — API smoke
- `test_benchmarks.py`
- `test_context_builder.py`
- `test_dense_context.py`
- `test_installer_tools.py`
- `test_mode_profiles.py`
- `test_phase_handlers.py`
- `test_reporting.py`
- `test_resume_and_retry.py`
- `test_skills.py`
- `test_updater.py`
- `test_vuln_intel.py`
- `test_workflow_engine.py`

Good footprint for functional paths. Absent:

## Missing Tests (ranked)

### Critical gaps
1. **Auth bypass regression** — assert booting with empty `SECOPS_API_TOKEN` fails in non-dev mode; assert every router returns 401 when token missing/wrong.
2. **Scope enforcement** — parameterize over in-scope / out-of-scope / RFC1918 / 169.254.169.254 / localhost; expect rejection.
3. **Approval-gate bypass** — creating a run with `ports=[...]` must NOT downgrade action kind.
4. **Redaction** — fixture-driven: feed a stdout with GitHub PAT, AWS key, JWT, Bearer header, private key; assert none leak into persisted event.
5. **Retry/replan** — state-transition integration test: fail a phase, call `/retry`, assert phase re-executes and new WorkflowPhaseRun row is created.

### High-value gaps
6. **Policy enforcement** — `ExecutionPolicyService.evaluate` coverage matrix.
7. **Prompt injection** — feed adversarial model output, assert it cannot change action kind / target.
8. **Multi-worker claim contention** — 5 threads claim 50 phases; assert exactly-once.
9. **SSE stream lifecycle** — connect, receive events, disconnect; no leaked threads.
10. **Pagination** — ensure list endpoints honor `limit`/`after` once implemented.

### Medium-value gaps
11. **Frontend unit tests** — `calcRisk`, `SEV` mapping, tab routing, `refreshRun` error surfacing. Vitest baseline.
12. **Frontend demo/real-mode toggle** — assert demo never activated by backend 500.
13. **Schema migrations** — Alembic upgrade/downgrade round-trips.
14. **Concurrency** — `pytest-xdist` safe test isolation (per-worker DB file).

### Low but worth it
15. **Subprocess timeout** — assert long-running command is killed at `timeout`.
16. **Graceful shutdown** — assert lifespan hook releases leases.
17. **Healthz vs readyz** — assert readyz fails when DB unreachable.
18. **Config defaults** — assert the three execution flags default to False.

## Suggested Directory Layout

```
tests/
  security/
    test_auth.py
    test_scope.py
    test_redaction.py
    test_policy_gates.py
    test_prompt_injection.py
  reliability/
    test_retry_replan.py
    test_worker_contention.py
    test_shutdown.py
  frontend/   # or frontend/src/__tests__/
```

## CI Recommendations

- Add `pip-audit` and `pnpm audit` as gating steps.
- Add a `pytest --maxfail=1` security lane that runs `tests/security/` on every PR.
- Add a `vitest` lane for frontend.
- Collect coverage with a floor (start at 60%, ratchet up).
