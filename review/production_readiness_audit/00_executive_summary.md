# Executive Summary — Production Readiness Audit

**Date:** 2026-04-19
**Scope:** Full repository (backend, frontend, workflow engine, policies, scripts, tests).
**Auditor role:** senior staff engineer + application security reviewer + production-readiness auditor.
**Verdict:** **DO NOT DEPLOY TO PRODUCTION.**

## Overall Rating: **4.2 / 10**

A capable prototype with good architectural bones (workflow engine with optimistic locking, phase lifecycle, structured events, decent test footprint), but shipping it to production as-is would create a *hostile-network-facing, unauthenticated, arbitrary-subprocess executor*. Fundamental identity/authz boundaries, scope enforcement, secret handling, and multi-process/multi-worker correctness are not yet production-grade.

## Top 10 Production Blockers

| # | ID | Severity | Title |
|---|----|----------|-------|
| 1 | PRA-001 | Critical | API token defaults to empty string → **all API endpoints are publicly reachable** when `SECOPS_API_TOKEN` is unset |
| 2 | PRA-002 | Critical | No target scope enforcement — `recon` + subprocess execution will scan any IP/host the operator types |
| 3 | PRA-003 | Critical | Approval gate for `recon_high_noise` is bypassable by supplying `ports` in run config |
| 4 | PRA-004 | Critical | `enable_write_execution`, `enable_codex_execution`, `enable_script_execution` all default **True** — a dev-friendly default is a prod footgun |
| 5 | PRA-005 | High | No CORS policy, no rate limiting, no request-id middleware, no structured auth audit log |
| 6 | PRA-006 | High | Secret redaction in `policies.run_subprocess` misses GitHub PATs, AWS keys, JWTs, Bearer headers, private keys, session cookies |
| 7 | PRA-007 | High | Worker runtime is a module-level threading singleton sized by `os.getpid()` at import time → incorrect under gunicorn/uvicorn multi-worker, unsafe under fork |
| 8 | PRA-008 | High | `/runs/{id}/retry` and `/replan` only flip `run.status = "queued"` — workflow/phase state is never reset, producing stuck-phase retries |
| 9 | PRA-009 | High | Frontend trusts `config/api` token as plaintext and persists it in `localStorage` — XSS-exfiltratable, no CSP |
| 10 | PRA-010 | High | Zero frontend tests, zero security regression tests, zero scope/policy-enforcement tests |

## Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High     | 14 |
| Medium   | 19 |
| Low      | 11 |
| Nit      | 7 |
| **Total**| **55** |

## Would I Approve This for Production Today?

**No.** Not until all Critical and High findings are resolved and regression tests exist to prevent recurrence. See `07_remediation_plan.md` for the phased plan. Earliest realistic prod-ready date assuming focused effort: **4–6 weeks**.
