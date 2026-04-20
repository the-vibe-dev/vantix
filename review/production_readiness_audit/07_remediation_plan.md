# Remediation Plan (Phased)

Each phase has an exit criterion and a gating test. No phase is "done" without green tests.

---

## Phase 0 — Stop-the-Bleeding (Day 1, 4–6 hours)

Goal: make an accidentally-exposed instance safe by default.

- [ ] PRA-001: Fail-closed auth. `secops/security.py` always compares; startup refuses empty token in non-dev.
- [ ] PRA-004: Flip `enable_write_execution`, `enable_codex_execution`, `enable_script_execution` to `False` default.
- [ ] PRA-003: Remove ports-based action-kind downgrade in `execution.py:206`.
- [ ] PRA-040: `.gitignore` the ops zips.

**Gate:** new `tests/security/test_auth.py` + `test_policy_gates.py` green.

---

## Phase 1 — Scope & Redaction (Days 2–4)

Goal: make scans legally safe and stop leaking secrets.

- [ ] PRA-002: Engagement scope model + enforcement; private/link-local denied by default.
- [ ] PRA-011: Expanded redaction patterns + truncation cap.
- [ ] PRA-045: Redact on fact/vector persistence.
- [ ] Unit tests for all of the above.

**Gate:** `tests/security/test_scope.py`, `test_redaction.py` green.

---

## Phase 2 — Ops Hygiene (Days 5–7)

- [ ] PRA-012: CORS allowlist, request-id middleware, limiter on privileged routes, audit log model.
- [ ] PRA-026: Global exception handler returning opaque errors.
- [ ] PRA-034: `structlog` + JSON logs bound to `run_id`/`phase`/`worker_id`.
- [ ] PRA-041: Split `/healthz` vs `/readyz`.
- [ ] PRA-042: Lifespan shutdown hook releases leases.

**Gate:** integration test for request-id propagation, audit log written for approve/cancel.

---

## Phase 3 — Reliability & Retry (Week 2)

- [ ] PRA-008: `RunService.retry` / `replan` transactionally reset phase state.
- [ ] PRA-019: Single UoW per phase execution in `execution.py`.
- [ ] PRA-007: Split worker into standalone process OR add DB-backed leader election.
- [ ] Subprocess timeout enforcement.

**Gate:** `tests/reliability/test_retry_replan.py`, `test_worker_contention.py` green.

---

## Phase 4 — Frontend & UX (Week 2–3)

- [ ] PRA-030: surface endpoint errors.
- [ ] PRA-031: demo mode explicit-only toggle.
- [ ] PRA-013/014: move token to httpOnly cookie OR introduce token table with rotation.
- [ ] PRA-033: vitest + smoke tests.
- [ ] CSP header middleware.

**Gate:** vitest lane green; manual browser review.

---

## Phase 5 — Data & Schema (Week 3)

- [ ] Move to Postgres + Alembic migrations.
- [ ] PRA-024: composite indexes on hot queries.
- [ ] PRA-027: pagination cursors on list endpoints.
- [ ] PRA-022: terminal delta endpoint `?since=`.

**Gate:** load test with 100k events stays under p95 < 200 ms.

---

## Phase 6 — Observability & Metrics (Week 3–4)

- [ ] Prometheus metrics + dashboards.
- [ ] Alert rules: phases stuck pending > 5m, lease churn, auth failures/min.
- [ ] Runbook docs (non-local) for each alert.

**Gate:** synthetic alert fires in staging.

---

## Phase 7 — Hardening & Privacy (Week 4+)

- [ ] PRA-015: prompt-injection hardening (schema-validated model output; no model-chosen action kinds).
- [ ] PRA-016: installer signature verification.
- [ ] PRA-017: provider key encryption at rest.
- [ ] PRA-044: operator-note classification UX.
- [ ] PRA-046: retention TTLs + cleanup job.

**Gate:** `tests/security/test_prompt_injection.py`; key encryption round-trip test.

---

## Entry Criteria for Production

1. All Phase 0–3 items closed.
2. Phase 4 items 1–3 closed (token storage model chosen).
3. Security test lane green, coverage ≥ 60% overall, ≥ 80% on `secops/services/policies.py`, `secops/security.py`, `secops/services/execution.py`.
4. Signed-off runbook covering: token rotation, scope policy, incident response, data retention.
5. Externally reviewed threat model + pen-test of the deployed instance.
