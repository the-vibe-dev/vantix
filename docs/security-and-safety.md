# Security and Safety

## Authorized Use

Vantix is for authorized defensive security testing only. Operators are responsible for scope, approvals, and legal authorization.

## Scope and Policy Controls

Execution actions are evaluated in `secops/services/policies.py` with verdicts:

- `allow`
- `allow_with_audit`
- `require_approval`
- `block`

Approval gates are used for higher-risk actions, including authenticated browser actions and sensitive route interaction.

## Runtime Permissions

Use a normal user account. Default runtime root is user-owned (`SECOPS_RUNTIME_ROOT`). Avoid running API/workers with `sudo`.

Checks:

```bash
bash scripts/doctor.sh
bash scripts/memory-health.sh
```

Repair user-owned runtime paths only:

```bash
bash scripts/fix-permissions.sh --apply
```

## Secret Hygiene

- Do not commit `.env`, provider keys, target credentials, or private topology.
- Keep local operator data in ignored files/directories.
- API tokens and secrets should be passed through env or local runtime config, never repository markdown.

## Browser Assessment Safety

- Browser runs are scope-limited to allowed origins/hosts.
- Authenticated testing requires operator-provided credentials and approval.
- Sensitive request headers/cookies are redacted from stored summaries.
- No brute-force or credential-attack logic is supported.

## Evidence Discipline

Treat outputs in three layers:

1. Observation artifacts
2. Hypothesis vectors/attack-chains
3. Validated findings

Promotion from observation to finding must be evidence-backed and policy-compliant.
