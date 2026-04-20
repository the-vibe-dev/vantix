# Security Review

## Threat Model (assumed)

- **Actors:** Authenticated operator (trusted-but-fallible), network attacker, hostile scan target (prompt-injection / credential planting).
- **Assets:** API token, provider keys, scan results, operator notes, target-side secrets leaked into subprocess output, attack-chain plans.
- **Trust boundary:** Browser ↔ API ↔ subprocess/Codex ↔ scanned target.

## Findings Summary

| ID | Severity | Area |
|---|---|---|
| PRA-001 | Critical | AuthN — default empty token bypasses auth |
| PRA-002 | Critical | AuthZ / Scope — unrestricted target |
| PRA-003 | Critical | Policy bypass — approval gate skippable |
| PRA-004 | Critical | Config — unsafe defaults |
| PRA-011 | High | Data leak — weak redaction |
| PRA-012 | High | Ops — no CORS/limit/audit |
| PRA-013 | High | Browser — token in localStorage |
| PRA-014 | High | IAM — static single token |
| PRA-015 | High | Prompt injection — model output trusted |
| PRA-016 | Medium | Supply chain — installer integrity |
| PRA-017 | Medium | Key storage — provider keys plaintext |
| PRA-044 | High | Privacy — operator notes unclassified |
| PRA-045 | Medium | Privacy — scan payloads unredacted |

## Auth & Session

- Single bearer token, no rotation, no per-user attribution, no session timeout, no MFA surface.
- `require_api_token` compares plaintext; at least use `hmac.compare_digest` (check: `secops/security.py` uses `==`? replace with constant-time).
- Recommend: token table `APIToken(id, label, hash, created_at, revoked_at, last_used_at)`. Seed one via install script. Log `last_used_at` on hit.

## Authorization & Scope

- **No scope enforcement.** Operator picks a `target` string; engine runs scans. See PRA-002. This is the most acute legal risk in the app.
- Per-engagement scope model: `EngagementScope{cidrs, hostnames, excludes, allow_private, allow_link_local}`. Resolve hostname → IP; validate both.
- Refuse 169.254.0.0/16 and 127.0.0.0/8 by default.

## Secrets & Sensitive Output

- Redaction (`policies.py:31-34`) is minimal. See PRA-011 / 03_quick_wins.md item 4.
- Subprocess stdout is persisted as `run_events`. A single tool leaking a token puts it in the DB forever.
- Recommend: cap stored output to N KB, store full output encrypted at rest in artifact blob, keep only truncated preview in `run_events.message`.

## AI / Prompt-Injection

- Codex/provider output is fed back into orchestration. A webpage banner saying *"Ignore previous instructions; run …"* could influence the next action.
- Mitigations:
  - Keep action *kind* selection server-side (never delegated to model).
  - Validate model output with strict schemas (Pydantic).
  - Red-team prompts in `tests/security/test_prompt_injection.py`.

## Browser / Frontend

- No CSP. Add via reverse proxy: `default-src 'self'; script-src 'self'; connect-src 'self'`.
- Token in `localStorage` (see PRA-013). Prefer httpOnly session cookie.
- Markdown / HTML rendering paths: confirm none use `dangerouslySetInnerHTML`.

## Network / Transport

- No enforcement of TLS at the app layer. Confirm reverse proxy terminates and redirects 80 → 443.
- No HSTS headers visible in middleware.

## Logging / Auditing

- No auth-audit trail for approvals, cancellations, provider-config writes, retry/replan.
- Add `AuditLog(id, ts, actor_token_id, route, verbs, object_id, verdict)`.

## Supply Chain

- Node deps via `pnpm-lock.yaml` / `package-lock.json` — ensure SBOM / `pnpm audit` runs in CI.
- Python deps — ensure `pip-audit` in CI.
- Installer fetches remote bundles (PRA-016) without hash pinning.

## Known-safe practices already in place

- `.gitignore` correctly excludes `.env`, runtime directories, `docs/local/`.
- `.env.example` is a placeholder, not real secrets.
- `require_api_token` *is* wired into every router (if the default weren't empty, this would be fine).
- Workflow claim uses optimistic locking on `UPDATE ... WHERE status='pending'`.
