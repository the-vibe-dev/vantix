# Code Smells & Stupid Things

Blunt list. Includes footguns, shortcuts, and "this will bite someone at 2 AM" patterns.

## Stupid Things (rank order)

1. **Empty-string API token disables auth silently.** The fail-closed default is literally two lines. Not shipping those two lines is the single dumbest thing in this codebase. (`secops/security.py:13-14`)

2. **`action_kind = "script" if run.config_json.get("ports") else "recon_high_noise"`.** Reading this line for the first time is painful. A user-supplied config key changes the *policy class*. (`secops/services/execution.py:206`)

3. **Execution features default to `True`.** `enable_write_execution`, `enable_codex_execution`, `enable_script_execution`. Inverted secure-default across three separate flags.

4. **Retry and replan set `run.status = "queued"` and call it a day.** The entire workflow state is ignored. This is a two-line function pretending to be a feature. (`secops/routers/runs.py:182-201`)

5. **Terminal is concatenated from every event, forever, on every GET.** No pagination, no tail, no cap. Scales as long as your patience does. (`secops/routers/runs.py:246-248`)

6. **`worker_runtime` is a module-level daemon thread sized by `os.getpid()` at import.** Works great if you never deploy with more than one worker and never fork. (`secops/services/worker_runtime.py`)

7. **Secret redaction is a regex for `sk-` and one loose k:v pattern.** It'd fail a 10-minute pair review. Does not catch GitHub PATs, AWS keys, JWTs, Bearer headers, or private keys.

8. **`refreshRun` in the frontend swallows every per-endpoint error with `.catch(() => defaults)`.** A backend 500 becomes a cheerful empty UI. Operators will think the run is clean.

9. **Demo mode is triggered by backend unreachability.** A broken network silently turns the product into a marketing demo. (`frontend/src/App.tsx`)

10. **Token in `localStorage`, no CSP.** First reflected XSS exfils the operator. Classic.

11. **`config_json`, `metadata_json`, `error_json` — three free-form JSON blobs accessed with `.get(...)` in 30+ places.** Every access is a silent schema violation waiting to happen.

12. **`time.time()` stored as `selected_at`.** Somewhere downstream it'll hit a JSON date parser and the `.0` will be mistaken for a timezone.

13. **Magic strings for statuses.** `"pending"`, `"claimed"`, `"completed"`, `"failed"`, `"blocked"`, `"retrying"` scattered as raw strings. Inevitable typo → silent misroute.

14. **Broad `except Exception: pass` in a few installer/worker paths.** If it fails, you won't know, and tomorrow's ticket will be "why is the worker silent?".

15. **1500-line `App.tsx`.** Testable only as a whole. No hooks extracted. Shipping this means the next UI diff is also 1500 lines.

16. **Five untracked ops zips at repo root** (`pentagi`, `shannon`, `strix`, `vantix`, `vantix_upgrade_kit`). One careless `git add -A` away from a 400 MB commit.

17. **`dependencies=[Depends(require_api_token)]` is repeated on every router file.** Nothing stops a new router from forgetting it.

18. **`run.config_json.get("ports", [])` with no typecheck.** If `ports` is ever `"22,80"` (string), you'll scan the characters `'2','2',','...` — well, you won't, but *something* will get weird.

19. **SSE + polling both always active.** 2× the bandwidth for no gain. Nobody pressed "use both".

20. **No Alembic.** The first prod schema change is going to be "drop and recreate in staging and pray".

21. **Operator note writes to filesystem with `note.created_at.strftime(...)`.** Locale-dependent? Probably not. Timezone-dependent? Hopefully UTC. Worth checking.

22. **No `hmac.compare_digest` on token comparison.** Probably fine because the token is static, but timing-safe compare is free.

23. **`WorkerLease` TTL 90 s is long.** If a worker dies mid-phase, the next claimer waits a minute and a half. Either shorten the TTL or accept it explicitly in docs.

24. **`structlog` / `logging` / `print` are all used somewhere.** Pick one.

25. **No request ID propagation.** Finding a single failing operator interaction in logs is "grep for the timestamp and hope".

## Honorable mentions (smells, not stupid)

- Consistent naming mostly but not always (`XxxRead` vs `Xxx`).
- Some inline JSON construction would be cleaner as Pydantic models.
- `ContextBuilder.build(profile=..., target=..., ports=..., services=..., extra_tags=...)` — five positional-ish kwargs; consider a single `RunContext` object.
- `list_run_events` returning all events by default is the same smell as `list_runs` returning all runs — pattern not one-off.
