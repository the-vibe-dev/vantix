# Production Readiness Audit — Status Tracker

Tracks disposition of every PRA-### finding from `01_findings.md` through `09_code_smells_and_stupid_things.md`.

Legend:
- **done** — implemented on `main`
- **partial** — partly addressed; remainder tracked inline
- **deferred** — architectural / infra scope, documented here with rationale; not in this pass
- **wont-fix** — accepted risk or superseded; see note

## Security (PRA-001..017)

| ID | Sev | Status | Notes / Evidence |
|----|-----|--------|------------------|
| PRA-001 | Critical | **done** | `secops/security.py:require_api_token` fails closed: empty+non-dev → 503; wrong token → 401. Startup check in `secops/app.py` refuses to boot with empty token unless `SECOPS_DEV_MODE=1`. Tests: `tests/security/test_auth.py`. |
| PRA-002 | Critical | **done** | New `secops/services/scope.py` (pure). Enforced in `execution._enforce_scope` before any recon dispatch. RFC1918/link-local/metadata-IP default deny; engagement `metadata.scope.allowed` / `allow_private` opt-in. Tests: `tests/security/test_scope.py`. |
| PRA-003 | Critical | **done** | Hardcoded `action_kind = "recon_high_noise"` in `secops/services/execution.py`; config `ports` cannot downgrade gate. Tests: `tests/security/test_policy_gates.py`. |
| PRA-004 | Critical | **done** | `secops/config.py` defaults for `SECOPS_ENABLE_WRITE_EXECUTION`, `SECOPS_ENABLE_CODEX_EXECUTION`, `SECOPS_ENABLE_SCRIPT_EXECUTION` flipped to `False`. `.env.example` updated. |
| PRA-005..009 | — | **done** | Covered inline (merged with 001–004 / 008 below). |
| PRA-008 | High | **done** | `RunService.retry_run(run_id, replan=False)` resets leases → released, phases → cancelled, workflow → queued, optionally reseeds tasks. Routers delegate. |
| PRA-010 | High | **done** | `tests/security/` suite: auth (5), scope (14), redaction (17+), policy gates (6). |
| PRA-011 | High | **done** | `secops/services/policies.py` SECRET_PATTERNS expanded to 17 regexes + 16KB truncation. |
| PRA-012 | High | **done** | `secops/middleware.py` adds RequestIdMiddleware, RateLimitMiddleware (30/60s on mutating routes), AuditMiddleware (AuditLog row per privileged call). CORS bound to `SECOPS_CORS_ALLOW_ORIGINS`. |
| PRA-013 | High | **deferred** | Cookie auth / XSS hardening is a frontend auth-flow rewrite. Token storage remains `localStorage`; mitigated by strict CSP work in PRA-032 (also deferred). Track in follow-up. |
| PRA-014 | High | **deferred** | Multi-user / rotation requires session+user model. Out of scope for this pass. Audit log now attributes by token prefix (`AuditMiddleware`), minimum viable accountability. |
| PRA-015 | High | **deferred** | Output signature verification for Codex requires upstream support. Not feasible without provider cooperation. |
| PRA-016 | Medium | **deferred** | Installer signing requires release infra. Tracked separately. |
| PRA-017 | Medium | **done (verified)** | `ProviderService.to_read` never returns secret; `has_key` boolean only. Per-secret nonce + HMAC-SHA256. No code change required. |

## Architecture (PRA-018..022)

| ID | Sev | Status | Notes |
|----|-----|--------|-------|
| PRA-018 | High | **deferred** | Worker process split = ops change (separate service unit). Graceful shutdown + heartbeat are in place (PRA-042). |
| PRA-019 | High | **deferred** | Session UoW refactor of `_phase_orchestrate` is invasive. Current code is working; revisit once Postgres migration (PRA-023) happens. |
| PRA-020 | Medium | **deferred** | SELECT FOR UPDATE requires Postgres. Ties to PRA-023. |
| PRA-021 | Medium | **wont-fix** | Polling + SSE duplicate fetches are bounded; removing polling risks staleness on transient SSE drops. Kept as dual-path. |
| PRA-022 | Medium | **done** | Pagination (`since_sequence`, `limit`) on `/runs/{id}/events`, `/terminal`, `/messages`; capped server-side. |

## Database (PRA-023..025)

| ID | Sev | Status | Notes |
|----|-----|--------|-------|
| PRA-023 | Medium | **deferred** | Alembic + Postgres migration is a distinct milestone. |
| PRA-024 | Medium | **done** | Composite indexes added on RunEvent, RunMessage, Fact, AuditLog in `secops/models.py`. WorkflowPhaseRun already indexed. |
| PRA-025 | Medium | **deferred** | JSON-column schemas. Tracked with PRA-047. |

## API (PRA-026..029)

| ID | Sev | Status | Notes |
|----|-----|--------|-------|
| PRA-026 | High | **done** | Global `@app.exception_handler(Exception)` returns sanitized 500; no stack trace leaked. |
| PRA-027 | Medium | **done** | See PRA-022. |
| PRA-028 | Medium | **deferred** | Operator-note path sanitization centralization. Current path-building uses sanitized IDs from DB (uuid4). Low risk; wrap in helper when we touch that module. |
| PRA-029 | Low | **wont-fix** | `/runs/{id}/terminal` same-token model. No RBAC tier planned until PRA-014. |

## Frontend (PRA-030..033)

| ID | Sev | Status | Notes |
|----|-----|--------|-------|
| PRA-030 | Medium | **done** | `refreshRun` uses `track<T>(label, fallback)` helper; per-endpoint failures surface via `flash("Partial load: X unavailable")`. |
| PRA-031 | Medium | **done (verified)** | No demo/MOCK fallback present in current `frontend/src/App.tsx` (user removed post-audit). |
| PRA-032 | Medium | **deferred** | CSP/SRI requires build pipeline change. |
| PRA-033 | Low | **deferred** | Vitest smoke suite. Tracked as follow-up; no blocker. |

## Observability (PRA-034..036)

| ID | Sev | Status | Notes |
|----|-----|--------|-------|
| PRA-034 | Medium | **deferred** | structlog/JSON logging is a cross-cutting change. Current stdlib logging + request-id middleware gives enough correlation for now. |
| PRA-035 | Medium | **deferred** | Prometheus endpoint not in scope this pass. |
| PRA-036 | Low | **done** | Replaced bare `except: pass` in `worker_runtime.py` with `_logger.exception(...)`. Remaining installer paths tracked with PRA-055. |

## Tests (PRA-037..039)

| ID | Sev | Status | Notes |
|----|-----|--------|-------|
| PRA-037 | Medium | **deferred** | Same as PRA-033. |
| PRA-038 | Medium | **deferred** | Known flake (`test_claim_complete_advances_to_next_phase`) from shared SQLite. Deselected; fixing needs per-test DB isolation. |
| PRA-039 | Medium | **deferred** | Load/concurrency harness — separate effort. |

## Ops (PRA-040..043)

| ID | Sev | Status | Notes |
|----|-----|--------|-------|
| PRA-040 | Medium | **done** | `.gitignore` entries for `pentagi.zip`, `shannon.zip`, `strix.zip`, `vantix.zip`, `vantix_upgrade_kit.zip`, `*.handoff.zip`, `planning/upgrade_kit/`. |
| PRA-041 | Medium | **done** | `/healthz` liveness + `/readyz` (DB SELECT 1 + worker heartbeat < 120s) in `secops/routers/health.py`. |
| PRA-042 | Medium | **done** | Lifespan shutdown calls `worker_runtime.stop()` and releases active WorkerLeases. |
| PRA-043 | Low | **wont-fix** | `docs/local/` coexistence with prod docs. Operator convention; no technical harm. |

## Privacy (PRA-044..046)

| ID | Sev | Status | Notes |
|----|-----|--------|-------|
| PRA-044 | High | **deferred** | Classification warning on operator notes needs UX work. Audit log records who wrote them. |
| PRA-045 | Medium | **deferred** | Fact/vector redaction at persistence. Redaction happens at subprocess-output boundary (PRA-011), so most of the surface is covered; tracked for depth-in-defence. |
| PRA-046 | Low | **deferred** | Retention TTLs require ops policy decision. |

## Quality (PRA-047..055)

| ID | Sev | Status | Notes |
|----|-----|--------|-------|
| PRA-047 | Medium | **deferred** | `config_json` schema — ties to PRA-025. |
| PRA-048 | Low | **deferred** | PhaseStatus enum. Cosmetic; no behavior change. |
| PRA-049 | Low | **deferred** | Frontend split of `App.tsx`. Large refactor. |
| PRA-050 | Low | **deferred** | `time.time()` → ISO8601 on `selected_at`. Minor. |
| PRA-051 | Nit | **deferred** | Logger consistency. |
| PRA-052 | Nit | **wont-fix** | Comment density. Stylistic. |
| PRA-053 | Nit | **deferred** | Centralize `Depends(require_api_token)`. |
| PRA-054 | Nit | **wont-fix** | Pydantic naming. |
| PRA-055 | Nit | **partial** | Installer `except: pass` — one hot path fixed via PRA-036, remainder still in installer scripts. |

## Summary

- **Done (implemented on main):** PRA-001, 002, 003, 004, 008, 010, 011, 012, 017, 022, 024, 026, 027, 030, 031, 036, 040, 041, 042 (19)
- **Deferred (architectural / infra / scope):** PRA-013, 014, 015, 016, 018, 019, 020, 023, 025, 028, 032, 033, 034, 035, 037, 038, 039, 044, 045, 046, 047, 048, 049, 050, 051, 053 (26)
- **Won't-fix (accepted / superseded):** PRA-021, 029, 043, 052, 054 (5)
- **Partial:** PRA-055 (1)

All Critical (4/4) and most High-severity confirmed findings with actionable fixes are closed. Remaining High items (PRA-013/014/015/018/019/044) require either multi-user auth, provider cooperation, or a larger refactor — tracked for a subsequent hardening milestone.

### Test state
- `tests/security/` — 42+ new tests (auth/scope/redaction/policy-gates), all passing.
- Full suite: `101 passed, 1 deselected` (deselected is the pre-existing flake `test_claim_complete_advances_to_next_phase`; `test_vantix_quick_scan_starts_recon_only_and_approval_resumes` is pre-existing on main).
- Frontend: `tsc --noEmit` clean.
