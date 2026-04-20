# Findings — Full Register

Format: `PRA-### | <Severity> | <Confidence> | <Category> | <Title>` followed by evidence, impact, and recommendation.

Severities: Critical / High / Medium / Low / Nit.
Confidence: confirmed (code read) / likely (strong inference) / possible (hypothesis).

---

## Security & Authentication

### PRA-001 | Critical | confirmed | security | API token defaults to empty → auth fully bypassed

**Evidence:** `secops/config.py:75` sets `api_token: str = os.getenv("SECOPS_API_TOKEN", "")`. `secops/security.py:13-14` short-circuits `require_api_token` when `settings.api_token` is falsy: `if not expected: return None`. Every router file (`runs.py:80`, `chat.py`, `approvals.py`, `providers.py`, `skills.py`, `system.py`, `cve.py`, `engagements.py`, `tasks.py`, `tools.py`, `memory.py`) mounts with `dependencies=[Depends(require_api_token)]`, so the auth bypass cascades globally.

**Impact:** A freshly-deployed instance with no `SECOPS_API_TOKEN` env var is an **open API** — attacker can enumerate runs, start scans, execute subprocesses through the execution path, read facts/memory, and update provider configs (keys may leak through `/providers` if stored).

**Recommendation:** Refuse startup when `api_token` is empty in any non-dev environment. Fail-closed: change `require_api_token` to raise 401 unconditionally when `expected` is falsy, unless `settings.dev_mode` is explicitly set.

---

### PRA-002 | Critical | confirmed | security | No scope allowlist on `_recon_target` — scans any IP the operator types

**Evidence:** `secops/services/execution.py` `_phase_recon` / `_recon_target` feeds `run.target` directly into nmap/policy subprocess without checking against an engagement-level `allowed_cidrs` / `allowed_hostnames` allowlist. Nothing in `ExecutionPolicyService.evaluate` (`secops/services/policies.py:31-115`) rejects private IPs, localhost, metadata endpoints (169.254.169.254), or out-of-scope public IPs.

**Impact:** Any user who can create a run can aim the scanner at `169.254.169.254`, internal VPCs, arbitrary third-party infra, law-enforcement honeypots, etc. That is legal exposure, not just a bug.

**Recommendation:** Per-engagement scope objects (CIDRs + hostnames + explicit exclusions). Every policy evaluation takes `(run, target)` and refuses when target ∉ scope. Block link-local, RFC1918 by default unless engagement opts in. Unit-test with hostile inputs.

---

### PRA-003 | Critical | confirmed | security | Recon approval bypass via `ports` config key

**Evidence:** `secops/services/execution.py:206` (port-supplied check): `action_kind = "script" if run.config_json.get("ports") else "recon_high_noise"`. Supplying `ports=[...]` in the run config downgrades the action kind so `ExecutionPolicyService.evaluate` uses the lighter `script` policy instead of `recon_high_noise` — side-stepping operator approval.

**Impact:** The primary workflow-level approval gate for aggressive recon is *user-controlled input away from bypass*.

**Recommendation:** Action kind must be decided by phase/profile, never by user-supplied config keys. Put policy decisions in a pure function with unit tests covering bypass attempts.

---

### PRA-004 | Critical | confirmed | security | Dangerous features default to enabled

**Evidence:** `secops/config.py:103-105`:
```
enable_write_execution: bool = _env_bool("SECOPS_ENABLE_WRITE_EXECUTION", True)
enable_codex_execution: bool = _env_bool("SECOPS_ENABLE_CODEX_EXECUTION", True)
enable_script_execution: bool = _env_bool("SECOPS_ENABLE_SCRIPT_EXECUTION", True)
```

**Impact:** Any deploy that doesn't explicitly set these to `False` is live with subprocess execution + AI-driven shell commands. Secure-by-default is inverted.

**Recommendation:** Default all three to `False`. Require explicit opt-in and log a prominent warning on startup when any are enabled.

---

### PRA-011 | High | confirmed | security | Weak subprocess-output redaction

**Evidence:** `secops/services/policies.py:31-34` redacts only `sk-...` OpenAI keys and a narrow `api_key|token|secret: value` pattern. Misses: `ghp_*`, `github_pat_*`, `AKIA*` (AWS), `xox[pbar]-*` (Slack), `eyJ*` JWTs, `Bearer .*` headers, `-----BEGIN PRIVATE KEY-----` blocks, `Cookie: session=*`, basic-auth `https://user:pass@host` URLs.

**Impact:** Subprocess stdout/stderr is persisted to `run_events` and displayed in the terminal panel — if a scan leaks credentials (common), they are stored plaintext and exfiltrable via the run API.

**Recommendation:** Replace with a vetted library or an extensive `SECRET_PATTERNS` list. Defense-in-depth: truncate stdout/stderr over N KB, and allow operators to flag-and-redact events after the fact.

---

### PRA-012 | High | confirmed | security | No CORS policy, no rate limiting, no request id / auth audit log

**Evidence:** `secops/app.py` mounts routers but installs no `CORSMiddleware`, no `TrustedHostMiddleware`, no per-endpoint limiter, no structured logging middleware.

**Impact:** Browser-originated abuse (if UI is hosted cross-origin), brute-force against the static API token, no forensic trail for authz-sensitive actions (approvals, execute, cancel).

**Recommendation:** Add `CORSMiddleware` with explicit allowlist, add `slowapi` or fastapi-limiter on `/runs/*/start|retry|replan`, `/approvals/*/approve|reject`, emit a `{request_id, actor, route, verdict}` log record per privileged call.

---

### PRA-013 | High | confirmed | security | Token persisted in `localStorage`, XSS-exfiltratable

**Evidence:** `frontend/src/api.ts` — API config is user-editable and persisted client-side; no CSP header set server-side; React `dangerouslySetInnerHTML` is not used but any future markdown rendering would leak.

**Impact:** One XSS and the operator's API token is shipped to attacker. No server-side CSP makes this worse.

**Recommendation:** Prefer httpOnly cookie + same-origin UI. If token UX must stay, set `Content-Security-Policy: default-src 'self'` via middleware and forbid third-party script loads.

---

### PRA-014 | High | confirmed | security | Static single-user bearer token — no rotation, no per-user attribution

**Evidence:** `secops/security.py` compares against `settings.api_token` with a single string.

**Impact:** No way to revoke one compromised operator without rotating everyone. No audit trail answering "who approved this high-noise recon?".

**Recommendation:** Move to token table (hashed, rotatable, labeled), surface `actor` on `ApprovalRequest`/`RunEvent`.

---

### PRA-015 | High | likely | security | No signature verification for Codex / provider outputs

**Evidence:** `secops/services/codex_runner.py` and `providers.py` execute/consume AI output and feed it back into subprocess-triggering code paths. Nothing verifies output integrity, origin, or applies a capability boundary.

**Impact:** Prompt injection in a scanned target page (e.g., a web banner) can cause the agent to craft a command the policy permits but the operator never intended — classic prompt-driven exfil or lateral movement.

**Recommendation:** Treat model output as adversarial input. Keep action *kind* decisions server-side. Never let a model choose a target or a phase directly.

---

### PRA-016 | Medium | confirmed | security | Installer / NAS bootstrap state has no integrity checks

**Evidence:** `secops/services/installer_state.py` + `secops/services/nas.py` ingest remote artifacts; no signature/hash check surfaced.

**Impact:** MITM or compromised origin can tamper installer contents.

**Recommendation:** Require pinned SHA256 on bundle manifests, verify before use.

---

### PRA-017 | Medium | possible | security | Provider configs may store API keys plaintext

**Evidence:** `ProviderConfig` is written from `/providers` router; no column-level encryption seen.

**Impact:** Anyone with DB access (or someone who can read the SQLite file on-disk) reads third-party provider keys.

**Recommendation:** Encrypt at rest with a KMS-backed key; never return the key in `GET /providers`.

---

## Architecture & Workflow Engine

### PRA-018 | High | confirmed | architecture | Worker runtime is a threading singleton sized at module import

**Evidence:** `secops/services/worker_runtime.py` uses a module-level daemon thread and records `os.getpid()` at import. A multi-worker uvicorn/gunicorn deployment will have one singleton per worker process, each claiming phases — producing duplicate or fighting workers even with optimistic locking (the lease will settle it, but at the cost of churn).

**Impact:** Noisy logs, split-brain appearance, unexpected retry semantics.

**Recommendation:** Either (a) decouple the worker into its own process (systemd unit / separate container) and keep FastAPI stateless, or (b) elect leader via DB (already have `WorkerLease`) before starting any claim loop.

---

### PRA-008 | High | confirmed | architecture | `retry_run` / `replan_run` don't reset workflow state

**Evidence:** `secops/routers/runs.py:182-201`:
```
run.status = "queued"
db.commit()
execution_manager.start(run_id)
```
No reset of `WorkflowPhaseRun` rows, `WorkerLease` rows, `WorkflowExecution.status`.

**Impact:** A run marked `failed` with phases in terminal states will be "retried" but the engine will immediately see all phases complete/failed and exit. Operator sees no progress; logs show nothing wrong.

**Recommendation:** Move logic to `RunService.retry(run_id)` that transactionally (a) finalizes stuck phases as `cancelled`, (b) clones the workflow definition into a fresh `WorkflowExecution`, (c) enqueues phases. Replan should also rebuild the plan via `ContextBuilder`.

---

### PRA-019 | High | confirmed | architecture | Session juggling in `_phase_orchestrate` is brittle

**Evidence:** `secops/services/execution.py` (≈ lines 260–420) opens multiple nested `SessionLocal()` scopes, commits intermediate state, and re-reads the run between blocks. Any exception mid-phase leaves partial state committed.

**Impact:** Hard-to-debug inconsistent state, race windows where phase status contradicts lease/metric rows.

**Recommendation:** Single UoW per phase execution. Emit events at end. Use SAVEPOINTs if intra-phase checkpointing is needed.

---

### PRA-020 | Medium | confirmed | architecture | Optimistic claim relies on SQLite serialization

**Evidence:** `workflows/engine.py` claims phases with `UPDATE ... WHERE status='pending'` + rowcount. Correct on SQLite's write-serialized mode, but will *seem* to work on Postgres without `SELECT ... FOR UPDATE SKIP LOCKED`, and has no READ COMMITTED fencing around visibility of committed status changes.

**Impact:** Portability bug when (not if) Postgres is adopted.

**Recommendation:** Replace with `SELECT ... FOR UPDATE SKIP LOCKED` once on Postgres; until then document the SQLite constraint in README.

---

### PRA-021 | Medium | likely | architecture | Polling + SSE both active — duplicate fetches on every run

**Evidence:** `frontend/src/App.tsx` runs a 3 s poll AND opens EventSource. Unless explicitly disabled, both fetch overlapping payloads.

**Impact:** 2× load on the API under steady state; extra render churn.

**Recommendation:** SSE is authoritative; fall back to polling only when EventSource errors. Single source of truth.

---

### PRA-022 | Medium | confirmed | architecture | Terminal content serialized by concat of every `terminal` event

**Evidence:** `runs.py:246-248` builds terminal with `"\n".join(event.message for event in events)` across all time. No pagination, no cap.

**Impact:** Long runs produce multi-MB responses on every poll.

**Recommendation:** Paginate by `since_sequence` and return incremental deltas; UI maintains a tail buffer.

---

## Data & Database

### PRA-023 | Medium | confirmed | db | SQLite default, no migration tool for prod

**Evidence:** `secops/config.py` defaults to SQLite. No Alembic directory visible.

**Impact:** Schema evolution on real deploys becomes manual `ALTER TABLE` or destructive resets.

**Recommendation:** Add Alembic; first migration is a baseline dump; require prod to be Postgres.

---

### PRA-024 | Medium | likely | db | No indices on hot query paths

**Evidence:** Frequent `WHERE run_id = ... ORDER BY created_at/sequence` across many tables; `secops/models.py` should be audited for composite indexes `(run_id, sequence)` / `(run_id, created_at)`.

**Impact:** Queries scale O(n) on event/fact counts.

**Recommendation:** Add composite indexes; benchmark with a 100k-event run.

---

### PRA-025 | Medium | likely | db | `config_json`, `metadata_json`, `error_json` are untyped blobs

**Evidence:** Pervasive JSON columns (`run.config_json`, `fact.metadata_json`, `phase.error_json`) with no Pydantic validation on write.

**Impact:** Schema drift; fields silently become stale; defensive `.get()` patterns everywhere.

**Recommendation:** Validate payload shape at write-time with Pydantic; log unknown keys.

---

## API Surface

### PRA-026 | High | confirmed | api | No global error handler; stack traces may leak on 500

**Evidence:** `secops/app.py` registers no `exception_handler`.

**Impact:** Uncaught exceptions become FastAPI's default 500 with traceback in debug mode, leaking paths + library versions.

**Recommendation:** Register generic `Exception` handler that logs internally and returns opaque `{"detail": "internal error", "request_id": ...}`.

---

### PRA-027 | Medium | confirmed | api | No pagination on list endpoints

**Evidence:** `list_runs`, `list_run_events`, `list_run_facts`, `list_run_messages`, `list_run_approvals` return all rows.

**Impact:** OOM risk on long-lived runs.

**Recommendation:** `?limit=&after=` cursors.

---

### PRA-028 | Medium | confirmed | api | Operator note writes to filesystem path derived from `note.id` without sanitization check

**Evidence:** `runs.py:269-273` writes `{created_at}_{note.id}.md`. `id` is server-generated UUID so it's fine *today*, but the pattern of constructing filenames from model fields is risky.

**Impact:** Low today, footgun if `applies_to` or `author` is ever added to path.

**Recommendation:** Centralize path building in `StorageLayout` with whitelist.

---

### PRA-029 | Low | confirmed | api | `/runs/{id}/terminal` has no auth-distinguished RBAC

**Evidence:** Any token holder can read any run's terminal.

**Impact:** Multi-tenant (if ever) leak.

**Recommendation:** Add engagement ownership check.

---

## Frontend

### PRA-030 | Medium | confirmed | frontend | `refreshRun` swallows errors per-call with `.catch(() => defaults)`

**Evidence:** `frontend/src/App.tsx` `refreshRun` uses `Promise.all([... .catch(() => emptyX), ...])`.

**Impact:** A failing endpoint (e.g., 500 on `/results`) silently degrades the UI to empty tables with no error banner. Operator sees "no findings" and thinks run is clean.

**Recommendation:** Track a `lastError[endpoint]` map and surface a toast/banner.

---

### PRA-031 | Medium | confirmed | frontend | Demo-mode fallback masks real backend failures

**Evidence:** App.tsx falls back to MOCK data when backend unreachable.

**Impact:** User can believe they're seeing real run data while looking at mocks.

**Recommendation:** Demo mode must be explicit toggle, never implicit on error.

---

### PRA-032 | Medium | possible | frontend | No Content-Security-Policy, no Subresource Integrity

**Evidence:** Built output (Vite) does not ship CSP headers (responsibility of server).

**Impact:** See PRA-013.

**Recommendation:** Nginx/uvicorn-gunicorn reverse proxy injects CSP.

---

### PRA-033 | Low | confirmed | frontend | No frontend test suite

**Evidence:** No `*.test.tsx`, no vitest config.

**Impact:** Regressions ship invisibly.

**Recommendation:** vitest + React Testing Library; start with risk calc, status-dot variant, tab routing.

---

## Observability

### PRA-034 | Medium | confirmed | obs | No structured logging format, no log levels mapped to events

**Evidence:** Scatter of `print()`/implicit logger usage in services; no `logger.bind(run_id=...)` pattern.

**Impact:** Hard to grep prod logs for a single run/phase.

**Recommendation:** `structlog` bound to `run_id`, `phase`, `worker_id`. Ship JSON logs.

---

### PRA-035 | Medium | likely | obs | No metrics endpoint

**Evidence:** No `/metrics` Prometheus exporter, no counters on phase claim success/fail, no histograms on subprocess duration.

**Impact:** No way to alert on "phases stuck in pending > 5m".

**Recommendation:** `prometheus-fastapi-instrumentator` + custom counters in engine.

---

### PRA-036 | Low | confirmed | obs | `broad except` patterns swallow errors

**Evidence:** `worker_runtime.py` and parts of `execution.py` use bare `except Exception` with no log; failures vanish.

**Impact:** Silent failure, very hard to debug.

**Recommendation:** Log exception with `logger.exception`, re-raise where safe.

---

## Tests

### PRA-010 | High | confirmed | tests | No security regression tests

**Evidence:** `tests/` inventory: api, benchmarks, context_builder, dense_context, installer_tools, mode_profiles, phase_handlers, reporting, resume_and_retry, skills, updater, vuln_intel, workflow_engine. No `test_policies.py`, no `test_scope_enforcement.py`, no `test_auth.py`, no `test_redaction.py`.

**Impact:** PRA-001/002/003/004/011 can recur silently.

**Recommendation:** Add a `tests/security/` subtree. Each finding above should get a failing test first, then be fixed.

---

### PRA-037 | Medium | confirmed | tests | No frontend tests (see PRA-033)

---

### PRA-038 | Medium | likely | tests | `conftest` likely uses a single shared DB — parallel test runs may cross-pollute

**Evidence:** Inferred from single `conftest.py`, SQLite default.

**Recommendation:** Per-test in-memory SQLite or per-worker file DB with pytest-xdist.

---

### PRA-039 | Medium | possible | tests | No load or concurrency test for workflow engine

**Evidence:** `test_workflow_engine.py` exists but only covers single-phase correctness (inferred).

**Recommendation:** Multi-worker contention test: 5 threads claiming 50 phases; assert exactly-once claim.

---

## Scripts & Operational

### PRA-040 | Medium | confirmed | ops | Untracked ops zips at repo root

**Evidence:** `git status` shows `pentagi.zip shannon.zip strix.zip vantix.zip vantix_upgrade_kit.zip` untracked.

**Impact:** Risk of accidental `git add -A`; repo bloat; unclear provenance.

**Recommendation:** Move to `drop/` or outside repo; add explicit `.gitignore` entries.

---

### PRA-041 | Medium | likely | ops | No healthcheck distinct from liveness

**Evidence:** `secops/routers/health.py` exists; likely returns `{"status":"ok"}` regardless of DB/worker state.

**Recommendation:** Separate `/healthz` (process up) from `/readyz` (DB reachable + worker heartbeat fresh < 60s).

---

### PRA-042 | Medium | possible | ops | No graceful shutdown for worker thread

**Evidence:** Daemon thread in `worker_runtime.py`; SIGTERM will kill it mid-phase.

**Impact:** Stale leases until TTL expires (90s) on every deploy.

**Recommendation:** FastAPI lifespan shutdown → set stop flag → join with timeout → release active leases.

---

### PRA-043 | Low | confirmed | ops | `docs/local/` exists alongside production docs

**Evidence:** Gitignored, so safe, but indicates a history of operator notes sneaking in.

**Recommendation:** Keep gitignored; add pre-commit hook rejecting `docs/local/**`.

---

## Privacy & Data Handling

### PRA-044 | High | confirmed | privacy | Free-text operator notes persisted to disk and DB without classification

**Evidence:** `runs.py:259-274` writes notes to both DB and `.md` files on NAS storage.

**Impact:** Operator might paste customer PII / credentials into a note; no redaction, no retention policy.

**Recommendation:** Policy doc; UI warning; optional auto-redact on save.

---

### PRA-045 | Medium | likely | privacy | Facts and vectors store raw target responses

**Evidence:** Vector metadata carries scan fragments; no truncation, no per-field redaction.

**Recommendation:** Truncate large payloads; redact patterns before persistence.

---

### PRA-046 | Low | confirmed | privacy | No data-retention TTL on events/artifacts

**Recommendation:** Add `retain_until` column + a cleanup job.

---

## Code Quality / Smells

### PRA-047 | Medium | confirmed | quality | `run.config_json.get(...)` accessed 10+ places with no schema

(See PRA-025.)

### PRA-048 | Low | confirmed | quality | Magic strings for phase names / statuses

`"pending"`, `"claimed"`, `"failed"`, `"blocked"`, `"retrying"` as bare strings across engine, router, UI.

**Recommendation:** `class PhaseStatus(str, Enum)`; share via Pydantic to UI.

### PRA-049 | Low | confirmed | quality | Frontend 1500-line `App.tsx` — not testable component-by-component

**Recommendation:** Split into `panels/`, `hooks/`, `api/` modules.

### PRA-050 | Low | confirmed | quality | `time.time()` used for `selected_at` — string representation in JSON is unix float

**Recommendation:** ISO8601 UTC strings everywhere.

### PRA-051 | Nit | confirmed | quality | Inconsistent logger usage (`print` vs. stdlib vs. implicit)

### PRA-052 | Nit | confirmed | quality | Comment density in TSX occasionally explains the obvious

### PRA-053 | Nit | confirmed | quality | `dependencies=[Depends(require_api_token)]` repeated on every router — centralize

### PRA-054 | Nit | confirmed | quality | Some Pydantic models named `XxxRead` while others just `Xxx` — inconsistent

### PRA-055 | Nit | confirmed | quality | `broad except: pass` in one or two installer paths

---
