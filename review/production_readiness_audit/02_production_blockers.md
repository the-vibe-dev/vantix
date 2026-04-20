# Production Blockers

These must be resolved before any production deployment. "Blocker" means a defect whose presence in prod creates unbounded risk (legal, security, or data-loss).

## Blockers (ordered by severity, then blast radius)

### 1. PRA-001 — Empty `SECOPS_API_TOKEN` default silently disables auth
- **Category:** Security / Config
- **Files:** `secops/config.py:75`, `secops/security.py:13-14`
- **Why it blocks prod:** One missing env var = publicly open API that can launch subprocesses.
- **Exit criteria:** Startup refuses to boot when `api_token` is empty unless `SECOPS_DEV_MODE=1`; `require_api_token` never returns without a comparison. Regression test: boot with empty token asserts SystemExit.

### 2. PRA-004 — Execution features default to enabled
- **Category:** Security / Config
- **Files:** `secops/config.py:103-105`
- **Why it blocks prod:** Operators that forget `SECOPS_ENABLE_*=false` get full subprocess + Codex execution.
- **Exit criteria:** Default each to `False`. Startup warns loudly when any are `True`. Test: `Settings()` default assertion.

### 3. PRA-002 — No target scope enforcement
- **Category:** Security / Legal
- **Files:** `secops/services/execution.py` (recon paths), `secops/services/policies.py`
- **Why it blocks prod:** Unauthorized scanning is a federal offense in many jurisdictions.
- **Exit criteria:** Engagement has `allowed_cidrs` + `allowed_hostnames`; all recon/exploit actions resolve target and refuse unless contained; private/link-local/metadata IPs denied by default.

### 4. PRA-003 — Approval bypass via `ports` config
- **Category:** Security
- **Files:** `secops/services/execution.py:206`
- **Why it blocks prod:** The approval gate is trivially bypassable by user-controlled input.
- **Exit criteria:** `action_kind` comes from phase/profile; user config cannot alter it. Test that supplying ports does not change action kind.

### 5. PRA-011 — Weak secret redaction
- **Category:** Security / Privacy
- **Files:** `secops/services/policies.py:31-34`
- **Why it blocks prod:** Subprocess output is persisted; scans commonly surface credentials.
- **Exit criteria:** A vetted redaction pass covers GitHub / AWS / JWT / Bearer / private-key / cookie / basic-auth URL patterns. Unit test with fixture strings.

### 6. PRA-008 — Retry/replan don't reset workflow state
- **Category:** Reliability
- **Files:** `secops/routers/runs.py:182-201`
- **Why it blocks prod:** Operators rely on retry; current impl silently no-ops.
- **Exit criteria:** `RunService.retry` & `RunService.replan` reset phase rows transactionally; integration test asserts phases re-execute.

### 7. PRA-007 — Worker singleton incorrect under multi-worker deploys
- **Category:** Reliability / Correctness
- **Files:** `secops/services/worker_runtime.py`
- **Why it blocks prod:** Default uvicorn/gunicorn deploys with `--workers N` will spawn N claim loops.
- **Exit criteria:** Worker runs as a separate process OR elects leadership via `WorkerLease` before any claim.

### 8. PRA-012 — No CORS / rate-limit / auth-audit middleware
- **Category:** Security / Operations
- **Files:** `secops/app.py`
- **Why it blocks prod:** No forensic trail, no brute-force protection.
- **Exit criteria:** CORS allowlist, request-id middleware, limiter on privileged routes, JSON audit log with `{request_id, actor, route}`.

### 9. PRA-013 + PRA-014 — Static token in localStorage, no rotation
- **Category:** Security
- **Files:** `frontend/src/api.ts`, `secops/security.py`
- **Exit criteria:** httpOnly cookie session OR token table with rotatable hashed tokens. CSP header set.

### 10. PRA-010 — No security regression tests
- **Category:** Tests
- **Files:** `tests/`
- **Exit criteria:** `tests/security/` covers auth bypass, scope enforcement, redaction patterns, and approval-gate bypass. Must be green before any prod rollout.
