# Configuration

Vantix keeps the existing `SECOPS_*` environment variables for compatibility. Public docs and UI use the Vantix name; internal package names and table names are intentionally unchanged in v1.

| Variable | Default | Description |
| --- | --- | --- |
| `SECOPS_REPO_ROOT` | current clone | Project root. |
| `SECOPS_RUNTIME_ROOT` | `${XDG_STATE_HOME:-$HOME/.local/state}/ctf-security-ops/<repo-name>-<repo-hash>` | User-owned runtime data. Keep SQLite here on local storage. |
| `SECOPS_REPORTS_ROOT` | `$SECOPS_RUNTIME_ROOT/reports` | Backend reports/artifacts root. |
| `SECOPS_ARTIFACTS_ROOT` | unset | Backward-compatible alias for reports/artifacts when `SECOPS_REPORTS_ROOT` is unset. Also used by legacy shell scripts. |
| `SECOPS_SHARED_ROOT` | `$SECOPS_RUNTIME_ROOT` | Optional shared storage. Not required. |
| `SECOPS_DATABASE_URL` | `$SECOPS_RUNTIME_ROOT/secops.db` | SQLAlchemy database URL. |
| `SECOPS_API_TOKEN` | empty | Bearer token for protected API/MCP routes. |
| `VANTIX_SECRET_KEY` | empty | Preferred key for encrypting optional provider secrets. |
| `SECOPS_SECRET_KEY` | empty | Backward-compatible fallback secret key. |
| `SECOPS_CODEX_BIN` | `codex` | Codex CLI binary path/name. |
| `SECOPS_DEFAULT_MODEL` | `gpt-5.4` | Default model label for Codex prompts. |
| `SECOPS_DEFAULT_REASONING_EFFORT` | `medium` | Default reasoning effort label. |
| `SECOPS_CVE_SEARCH_URL` | `http://127.0.0.1:5000` | Local cve-search endpoint. |
| `SECOPS_ENABLE_CVE_MCP` | `false` | Mount CVE MCP endpoint in the FastAPI app. |
| `SECOPS_CVE_MCP_PATH` | `/mcp/cve` | Embedded CVE MCP path. |
| `SECOPS_CVE_MCP_REQUIRE_TOKEN` | `true` | Require bearer token for hosted MCP. |
| `SECOPS_ENABLE_VANTIX_MCP` | `false` | Mount Vantix white-box MCP endpoint. |
| `SECOPS_VANTIX_MCP_PATH` | `/mcp/vantix` | Embedded Vantix MCP path. |
| `SECOPS_SOURCE_ALLOWED_ROOTS` | repo root | Comma-separated allowlisted roots for local white-box source paths. |
| `SECOPS_SOURCE_UPLOAD_MAX_MB` | `500` | Maximum zip upload size for white-box source uploads. |
| `SECOPS_SOURCE_UPLOAD_TTL_HOURS` | `24` | Retention window for staged source uploads. |
| `SECOPS_UI_HOST` | `127.0.0.1` | Dev UI bind host used by `scripts/secops-ui.sh`. |
| `SECOPS_UI_PORT` | `4173` | Dev UI bind port used by `scripts/secops-ui.sh`. |
| `SECOPS_ENABLE_CODEX_EXECUTION` | `true` | Allow Codex execution manager actions. |
| `SECOPS_ENABLE_SCRIPT_EXECUTION` | `true` | Allow script adapter actions. |
| `SECOPS_ENABLE_WRITE_EXECUTION` | `true` | Allow write-capable execution actions. |
| `OPERATOR_NAME` | `operator` | Generic lab operator label. |

## Storage

Default runtime state is per-user and local:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/ctf-security-ops/<repo-name>-<repo-hash>
```

This avoids root-owned files, NFS SQLite locking problems, and broad permission repair. If an operator intentionally uses shared storage, they should own the directory and verify writes with `bash scripts/doctor.sh`.

## Provider Secrets

Provider records are optional. To store provider keys, configure `VANTIX_SECRET_KEY` or `SECOPS_SECRET_KEY`. API responses only expose `has_key`; raw secrets are never returned.

## Hygiene

Keep real hostnames, private paths, client names, SSH key names, API tokens, and topology in ignored local files. Do not commit `.env`, provider config with secrets, target-specific evidence, or client data.

## CVE Backfill

To seed a large CVE baseline (2019+ by default), run:

```bash
bash scripts/backfill-cve-intel.sh 2019 250000
```

The second argument controls per-source adapter limits for sidecar vuln-intel backfill.
