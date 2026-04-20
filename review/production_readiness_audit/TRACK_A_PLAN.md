# Plan: Complete Platform-Decision Remediation (Track A)

## Context

The production-readiness audit left 26 findings deferred because they depend on platform decisions (Postgres, multi-user, release signing). The user has now decided:

- **Postgres**: opt-in via `DATABASE_URL`; SQLite stays as dev default. Unblocks PRA-019/020/023 and implicitly PRA-025/047.
- **Multi-user auth**: full users + login + roles (admin/operator/viewer), httpOnly cookie. Unblocks PRA-013/014/029/044.
- **Release signing**: signed installer + NAS bootstrap integrity. Unblocks PRA-016.

After this pass, the only remaining deferred items should be pure style/refactor (PRA-049 App.tsx split, logger consistency, etc.) and build-pipeline work (PRA-032 CSP/SRI, PRA-034 structlog, PRA-035 Prometheus).

Outcome goal: all confirmed High findings closed with code + tests on `main`, Postgres path exercised in CI, release artifacts reproducibly signable.

Note: `vantix.zip` at the repo root is stale and out of scope; the release path is the installer scripts plus a newly-built tarball.

---

## Track 1 — Postgres + Alembic (PRA-019/020/023, partial 025/047)

**Good news from exploration:** Models already use portable `JSON`/`DateTime(timezone=True)`; `psycopg[binary]` is already pinned; `SECOPS_DATABASE_URL` env already honored in `secops/db.py:54`; SQLite pragmas are already dialect-guarded. This is mostly additive.

### 1.1 Introduce Alembic

- Add `alembic` to `pyproject.toml`.
- `alembic init alembic/` at repo root. Configure `alembic/env.py` to import `Base` from `secops.db` and `target_metadata = Base.metadata`.
- Point `sqlalchemy.url` dynamically at `settings.database_url` (don't hardcode in `alembic.ini`).
- Generate **baseline** revision `0001_baseline.py` via `alembic revision --autogenerate` from the current in-code schema. Review diff, commit.
- Replace `Base.metadata.create_all()` calls (currently only in `tests/test_workflow_engine.py:20`) — keep `create_all` for tests (fast) but add `alembic upgrade head` as the app-startup path for non-SQLite URLs.
- App startup (in `secops/app.py` lifespan, next to `_check_startup_config`): if dialect ≠ sqlite and not in test env → run `alembic upgrade head` in-process via `command.upgrade(cfg, "head")`.

### 1.2 Postgres-aware claim loop (PRA-020)

File: `secops/services/workflows/engine.py:119-236` (`claim_next_phase`).

- Detect dialect via `db.bind.dialect.name`.
- **Postgres path**: replace the two-step candidate-IDs + try-UPDATE loop with a single CTE:
  ```sql
  WITH c AS (
    SELECT id FROM workflow_phase_runs
    WHERE status IN ('pending','retrying')
       OR (status='claimed' AND lease_expires_at < :now)
    ORDER BY created_at ASC
    FOR UPDATE SKIP LOCKED LIMIT 1
  )
  UPDATE workflow_phase_runs SET status='claimed', ...
  WHERE id IN (SELECT id FROM c) RETURNING *;
  ```
  Emit via `db.execute(text(...))` + ORM re-fetch, or `select(...).with_for_update(skip_locked=True)` + ORM update.
- **SQLite path**: keep the current optimistic loop unchanged.
- Shared helper `_claim_with_for_update(db, worker_id, lease_seconds)` for the Postgres path; gate by dialect check.

### 1.3 Session UoW for `_phase_orchestrate` (PRA-019)

File: `secops/services/execution.py:553-625`.

Problem: outer `with SessionLocal() as db:` then three inner `with SessionLocal() as inner_db:` blocks — detached objects, cross-session commits.

- Flatten to a single session. Model as sequential UoWs separated by `db.flush()` (not nested sessions). Only `commit()` at state-machine boundaries (after successful phase transition).
- Where current code opens an inner session to "commit in isolation" (typically for audit/write-through on error), refactor to use savepoints: `with db.begin_nested():` then commit outer at end.
- After refactor, add a unit test that simulates mid-phase exception and asserts the outer session was rolled back cleanly (no orphan rows, no stale `run.status`).

### 1.4 CI matrix

- `.github/workflows/ci.yml` (or equivalent; if none exists, add one): run pytest twice — once against default SQLite, once with `SECOPS_DATABASE_URL=postgresql+psycopg://...` against a Postgres service container.
- Update `tests/conftest.py` — if `SECOPS_DATABASE_URL` is Postgres, drop and recreate schema via Alembic between test modules (or use a session-scoped fixture with `sqlalchemy-utils` `create_database`).

### 1.5 Docs

- `docs/operations/database.md`: how to provision Postgres, how to run migrations, rollback guidance.

**Files touched:** `pyproject.toml`, `alembic.ini` (new), `alembic/env.py` (new), `alembic/versions/0001_*.py` (new), `secops/app.py` (lifespan), `secops/services/workflows/engine.py`, `secops/services/execution.py`, `tests/conftest.py`, `.github/workflows/ci.yml`, `docs/operations/database.md` (new).

---

## Track 2 — Users + Login + Roles (PRA-013/014/029/044)

This is the largest track. Three layers: data model, auth flow, UI.

### 2.1 Data model

New tables (new Alembic revision `0002_users_and_roles.py`):

- `users`: `id (uuid)`, `username (unique)`, `password_hash` (argon2id via `passlib[argon2]`), `role` (enum: `admin`, `operator`, `viewer`), `disabled (bool)`, `created_at`, `last_login_at`.
- `user_sessions`: `id (uuid session token stored as sha256 hash)`, `user_id`, `created_at`, `expires_at`, `last_seen_at`, `remote_addr`, `user_agent`, `revoked (bool)`.

Mutate existing:
- `audit_log.actor` → keep string but now holds `user:{username}` or `token:…` (back-compat).
- `operator_notes.author` → populate from session user automatically; keep column.

New Pydantic models in `secops/schemas.py` / new `secops/schemas/auth.py`.

### 2.2 Auth service

New module `secops/services/auth_service.py`:

- `hash_password`, `verify_password` (argon2id).
- `create_session(user, remote_addr, user_agent) -> (raw_token, UserSession)` — returns 32-byte urlsafe token; persists SHA-256 hash only.
- `lookup_session(raw_token) -> (User, UserSession) | None` — rejects expired, revoked, or disabled-user sessions; bumps `last_seen_at`.
- `revoke_session`, `revoke_all_sessions_for_user`.
- Session TTL: 12h default, configurable via `SECOPS_SESSION_TTL_HOURS`.

### 2.3 Auth dependency replacement

Replace `secops/security.py`:

- Keep `require_api_token` **only** as a service-to-service fallback (off by default; enabled by `SECOPS_SERVICE_TOKEN_ENABLED=1`). When enabled, non-interactive clients can still pass `Authorization: Bearer`.
- New dependency `require_user(min_role: Role = Role.operator)`:
  - Read session cookie `vantix_session` (httpOnly, Secure, SameSite=Lax, Path=/).
  - Call `auth_service.lookup_session()`.
  - Compare role tier. Deny with 403 if below `min_role`.
- New dependency `require_csrf` for mutating routes (POST/PUT/DELETE):
  - Double-submit: read `X-CSRF-Token` header, compare to `vantix_csrf` cookie (non-httpOnly, SameSite=Lax). Constant-time compare.
  - Skip for service-token calls (those use Bearer, not cookies).
- Centralize: one `Depends(require_user(...))` per router (PRA-053 free win).

### 2.4 Login/logout endpoints

New router `secops/routers/auth.py`:

- `POST /api/v1/auth/login` (unauthenticated): `{username, password}` → sets `vantix_session` + `vantix_csrf` cookies, returns `{user: {username, role}, csrf: "..."}`.
- `POST /api/v1/auth/logout`: revokes session, clears cookies.
- `GET /api/v1/auth/me`: returns current user info (for frontend bootstrap).
- Rate-limit login: 5 attempts / 60s per remote_addr via existing `RateLimitMiddleware` (extend list).

### 2.5 Role enforcement — endpoint audit

Map every router to minimum role. New table in `docs/operations/rbac.md`:

| Route prefix | min role |
|--------------|----------|
| `/api/v1/runs` GET | viewer |
| `/api/v1/runs` mutations, `/terminal` | operator |
| `/api/v1/providers`, `/api/v1/system`, `/api/v1/engagements` mutations | admin |
| `/api/v1/modes`, `/api/v1/skills`, `/api/v1/tools` GET | viewer |

`/runs/{id}/terminal` closes PRA-029 by requiring `operator`.

### 2.6 Middleware

`AuditMiddleware` (secops/middleware.py:105-135): change actor resolution — if request has authenticated user (set by dependency via `request.state.user`), use `user:{username}`; else fall back to token prefix.

Operator-note write (PRA-044): router sets `note.author` from `request.state.user.username`, never trusts client input. Adds `classification_warning` field to POST schema (enum: `unrestricted`, `internal`, `sensitive`); frontend banner shown on write.

### 2.7 Frontend

Files: `frontend/src/api.ts`, `frontend/src/App.tsx`, new `frontend/src/Login.tsx`.

- Remove `localStorage["vantix_api_token"]` read/write. Delete `authHeaders()` and its callers — cookies travel automatically. Add `credentials: "include"` to every fetch.
- Replace token-paste ApiConfigPanel (App.tsx:1584-1629) with login form.
- On 401 from any API call → redirect to login.
- Bootstrap sequence: `GET /api/v1/auth/me` → if 401, show Login; else hydrate `user` into app state.
- Role-gate UI: hide mutate buttons (start/pause/retry/providers) for `viewer`; hide admin screens for `operator`.
- CSRF: read `csrf` from login response; persist in memory (not localStorage); attach `X-CSRF-Token` header to every mutating fetch.
- Operator note modal: add classification dropdown; show inline warning text.

### 2.8 Bootstrap admin

On first startup with empty `users` table and `SECOPS_ADMIN_USERNAME`/`SECOPS_ADMIN_PASSWORD` set: create the admin user, log to stdout. Startup check refuses to boot if users table is empty AND the env vars are unset AND not dev mode.

### 2.9 Tests

- `tests/security/test_users.py`: password hashing, session creation/lookup/expiry/revoke.
- `tests/security/test_auth_flow.py`: login happy path, wrong password, locked user, rate limit after 5 fails, logout revokes session, session TTL expiry.
- `tests/security/test_rbac.py`: viewer cannot mutate; operator cannot hit admin; admin hits everything; terminal requires operator (PRA-029 regression).
- `tests/security/test_csrf.py`: mutating POST without header → 403; with matching header → 200; with mismatched → 403.
- `tests/conftest.py`: helper `as_user(role)` that logs in via the test client and returns cookie jar.
- Update existing `tests/test_api.py` to authenticate via `as_user("operator")` rather than relying on `SECOPS_DEV_MODE=1`. Keep dev-mode as a separate fast-path covered by one test.

**Files touched:** `alembic/versions/0002_*.py` (new), `secops/models.py`, `secops/schemas.py`, `secops/services/auth_service.py` (new), `secops/security.py`, `secops/routers/auth.py` (new), all 14 routers (swap `require_api_token` → `require_user(...)`), `secops/middleware.py`, `secops/routers/runs.py` (note author from session), `secops/app.py` (bootstrap admin, startup check), `frontend/src/api.ts`, `frontend/src/App.tsx`, `frontend/src/Login.tsx` (new), `tests/security/*` (4 new files), `tests/conftest.py`, `tests/test_api.py`, `docs/operations/rbac.md` (new), `.env.example` (add `SECOPS_ADMIN_USERNAME`, `SECOPS_ADMIN_PASSWORD`, `SECOPS_SESSION_TTL_HOURS`).

---

## Track 3 — Release signing (PRA-016)

Minimal viable signing: cosign keyless via GitHub OIDC (no key custody), with local verification.

### 3.1 Release artifact + manifest

- New `scripts/build-release.sh`: produces `vantix-<version>-<sha>.tar.gz` of `secops/`, `frontend/dist/`, `scripts/install-vantix.sh`, `pyproject.toml`, `alembic/`, `docs/`. Excludes tests and the stale `vantix.zip` and the reference repo zips.
- Emits `manifest.json`: `{version, git_sha, files: [{path, sha256, size}], created_at}`.
- CI workflow `.github/workflows/release.yml` builds on tag push, runs cosign:
  ```
  cosign sign-blob --yes --output-signature vantix.sig --output-certificate vantix.pem vantix-*.tar.gz
  ```
  Uploads `tar.gz`, `manifest.json`, `vantix.sig`, `vantix.pem` as release assets.

### 3.2 Installer verification

- Extend `scripts/install-vantix.sh` (or the Python part it calls in `installer.py`): before unpacking the tarball,
  1. Download `manifest.json`, `vantix.sig`, `vantix.pem` alongside.
  2. Run `cosign verify-blob --certificate-identity-regexp 'github.com/<org>/<repo>' --certificate-oidc-issuer https://token.actions.githubusercontent.com --signature vantix.sig --certificate vantix.pem vantix-*.tar.gz`.
  3. After unpack, walk `manifest.json` and verify each file's SHA-256 matches. Refuse to proceed on mismatch.
- Require cosign on PATH; if absent, print a clear message with install command — don't silently skip.

### 3.3 Ollama installer pipe-to-bash (secondary)

File: `installer.py:469`. Replace `curl | sh` with: download the script, verify SHA-256 against a pinned value in `installer.py` (update process documented), then exec. This is not cosign but it removes the most dangerous MITM surface.

### 3.4 NAS bootstrap integrity

File: `secops/services/storage.py` — on `ensure()`, write `installer_state.json` with the release's git sha + manifest sha256. On subsequent boot, compare; if sha changed unexpectedly (version bump), log an audit record and require an operator confirmation flag (`VANTIX_ACCEPT_VERSION_CHANGE=<new_sha>`) before proceeding. Prevents silent tampering of deployed state.

### 3.5 Tests

- `tests/release/test_manifest.py`: build a fake tarball + manifest, corrupt one file, ensure verifier raises.
- Smoke `scripts/build-release.sh --dry-run` in CI to prevent drift.

**Files touched:** `scripts/build-release.sh` (new), `scripts/install-vantix.sh`, `installer.py`, `.github/workflows/release.yml` (new), `secops/services/storage.py`, `tests/release/test_manifest.py` (new), `docs/operations/release.md` (new).

---

## Sequencing

1. **Track 1.1 first (Alembic baseline).** Everything else adds tables, so we need the migration machinery before we can add `users`/`user_sessions`.
2. **Track 2** (auth). Biggest. Land data model + service + one router swap end-to-end first (prove the pattern), then sweep remaining routers.
3. **Track 1.2 + 1.3** (claim-loop + `_phase_orchestrate`). Safe to do in parallel with Track 2 since they touch different files.
4. **Track 3** (signing). Independent; can land anytime. Do last so it signs the post-remediation snapshot.
5. **Track 1.4** (CI matrix). After 1.1–1.3 land — both dialects must pass.

Estimated commits: 6–8 (one per logical slice, each with tests green).

## Verification

End-to-end acceptance checklist:

- [ ] `alembic upgrade head` brings an empty Postgres DB to current schema.
- [ ] Full pytest suite passes against **both** `sqlite+pysqlite` and `postgresql+psycopg`.
- [ ] Concurrency test: 10 worker threads race on `claim_next_phase` under Postgres, no double-claims, no deadlocks (new test).
- [ ] `frontend` builds clean, `tsc --noEmit` clean.
- [ ] Manual: fresh DB → startup creates admin from env → login → admin creates operator user → operator cannot access providers (403) → operator can start run → viewer cannot start run (403) → viewer cannot GET terminal (403).
- [ ] Logout revokes session immediately (subsequent call 401).
- [ ] CSRF: curl POST with cookie but no `X-CSRF-Token` → 403.
- [ ] `scripts/build-release.sh` produces tarball + manifest; `cosign verify-blob` succeeds in CI.
- [ ] Installer refuses to run when `manifest.json` SHA-256 of any file is altered.
- [ ] `review/production_readiness_audit/STATUS.md` updated: PRA-013/014/016/019/020/023/029/044 → **done**; partial items (025/047) noted.

## Out of scope for this pass

Still deferred after this work: PRA-032 (CSP/SRI), PRA-034 (structlog), PRA-035 (Prometheus), PRA-046 (retention TTLs), PRA-048 (enum refactor), PRA-049 (App.tsx split), PRA-050/051 (cosmetic). These are orthogonal and non-security-gating.
