# Quick Wins

High-value, low-effort fixes that materially reduce risk within a day or two. Ordered by (impact / effort).

## Top Quick Wins

### 1. Fail-closed auth (15 min)
- Edit `secops/security.py` to always compare; if `expected` is empty, raise 401.
- Edit `secops/app.py` or a lifespan hook to `sys.exit(1)` when `settings.api_token == ""` and `SECOPS_DEV_MODE != "1"`.
- Addresses **PRA-001**.

### 2. Flip execution defaults to False (5 min + docs)
- `secops/config.py:103-105` — change three defaults.
- Update `.env.example` + README to make the opt-in explicit.
- Addresses **PRA-004**.

### 3. Hardcode `action_kind` from phase (20 min)
- `secops/services/execution.py:206`: remove the ports-based downgrade. Always use phase-derived kind.
- Add one unit test to pin behavior.
- Addresses **PRA-003**.

### 4. Expand redaction patterns (1–2 h)
- Pull in a vetted regex list (trufflehog's set is a good baseline) and apply in `secops/services/policies.py:run_subprocess`.
- Unit-test 10 sample secrets.
- Addresses **PRA-011**.

### 5. Add CORS + request-id middleware (30 min)
- `CORSMiddleware` with env-driven allowlist.
- Tiny middleware assigning `request.state.request_id = uuid4()` and logging on each privileged route.
- Addresses part of **PRA-012**.

### 6. Global exception handler (15 min)
- Register one handler that returns `{"detail":"internal error","request_id":...}` and logs internally.
- Addresses **PRA-026**.

### 7. Fix retry/replan stub (1 h)
- Move logic into `RunService.retry`: cancel in-flight phases, clone WorkflowExecution, enqueue.
- Addresses **PRA-008**.

### 8. Don't mask failures in `refreshRun` (1 h)
- Replace `.catch(() => defaults)` with error bookkeeping; show toast.
- Addresses **PRA-030**.

### 9. Surface non-demo vs demo mode explicitly (15 min)
- Remove implicit demo fallback on error. Require explicit toggle in Config tab.
- Addresses **PRA-031**.

### 10. Add `.gitignore` entries for ops zips and rename `drop/` (5 min)
- Stop `pentagi.zip`, `shannon.zip`, `strix.zip`, `vantix*.zip` from showing in `git status`.
- Addresses **PRA-040**.

### 11. Add composite indexes (30 min)
- `CREATE INDEX ON run_event(run_id, sequence);` and similar for `fact`, `run_message`, `workflow_phase_run`.
- Addresses part of **PRA-024**.

### 12. Replace `print` with structured logger in services (1–2 h)
- Shared `logger = structlog.get_logger(...).bind(service="secops")`.
- Addresses **PRA-034**, **PRA-036**, **PRA-051**.
