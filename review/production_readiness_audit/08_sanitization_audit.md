# Sanitization & Data-Handling Audit

Scope: inbound user input, outbound API responses, subprocess stdout/stderr, persisted model columns, filesystem paths, and UI rendering.

## Inbound — HTTP request bodies

| Surface | Current validation | Risk | Recommendation |
|---|---|---|---|
| `POST /runs` (`RunCreate`) | Pydantic schema | `target` accepted as any string | Add domain validator: hostname / IP / CIDR; reject whitespace, control chars |
| `POST /runs/{id}/operator-notes` | Pydantic `OperatorNoteCreate` | No length cap; raw content → DB + disk | Cap `content` length (e.g., 16 KB); strip null bytes |
| `POST /runs/{id}/vectors` | Pydantic `VectorCreate` | Metadata is free-form JSON | Schema-validate known keys; whitelist |
| `POST /providers` | Pydantic `ProviderConfig` | API keys in payload | Never log; never echo on GET |
| `POST /chat` | (verify) | Free-text → model | Length cap; rate limit |

## Inbound — Configuration (`config_json`)

- `run.config_json.get("ports")` used to pick action kind (PRA-003). **Input-as-policy**.
- `services`, `tags`, `ports` extracted via `.get(...)` with no type assertions. A malformed payload can set `ports = "all"` (a string) and the engine may iterate characters.
- Recommend a `RunConfig` Pydantic model; store only validated shape.

## Outbound — API responses

| Endpoint | Leak risk |
|---|---|
| `GET /providers` | May return API keys. Must mask (`sk-...****`). |
| `GET /runs/{id}/terminal` | Returns raw subprocess output (see redaction below). |
| `GET /runs/{id}/events` | Same — `RunEvent.message` may contain leaked secrets. |
| `GET /runs/{id}/facts` | `metadata_json` may carry raw target-side data. |

## Subprocess output redaction

**Current** (`secops/services/policies.py:31-34`): redacts `sk-...` + one k:v pattern.

**Missing patterns** (to add):

```
ghp_[A-Za-z0-9]{36}                          # GitHub PAT
github_pat_[A-Za-z0-9_]{80,}                 # GitHub fine-grained PAT
AKIA[0-9A-Z]{16}                             # AWS access key ID
(?:^|[^A-Za-z0-9])[A-Za-z0-9/+=]{40}(?:[^A-Za-z0-9]|$)  # AWS secret (heuristic)
xox[pbar]-[A-Za-z0-9-]{10,}                  # Slack tokens
eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}  # JWT
-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END[^-]+-----
Bearer\s+[A-Za-z0-9._\-]+                    # Authorization headers
Authorization:\s*Basic\s+[A-Za-z0-9+/=]+
(?i)password[\"'\s:=]+[^\s\"']{4,}
(?i)passwd[\"'\s:=]+[^\s\"']{4,}
https?://[^\s:/@]+:[^\s@/]+@                 # userinfo URL
(?i)cookie:\s*[^\n]+
MIIB[A-Za-z0-9+/=]+                          # DER cert body heuristic
```

Also: cap stored event `message` at 8–16 KB; push full output to an artifact with restricted read path.

## Filesystem paths

- `secops/routers/runs.py:269-273` composes note filename from `note.id` (safe UUID) and timestamp. Safe today.
- `secops/services/storage.py` — audit path concatenations for any user-controlled component (workspace slug, engagement name). If user-controlled → sanitize via `re.sub(r"[^A-Za-z0-9._-]", "_", ...)`.

## Database

- JSON columns (`config_json`, `metadata_json`, `error_json`) are not validated on write. An operator can stuff arbitrary nested structures. Consider Pydantic parse on setter.
- No column-level encryption for provider keys.

## Frontend rendering

- Ensure no `dangerouslySetInnerHTML` is introduced when adding Markdown rendering (operator notes, chat). Prefer `react-markdown` with default sanitizer.
- Escape terminal content (currently rendered as text, good — keep it that way).
- Reject rendering of arbitrary HTML in approval descriptions.

## Logging

- Standardize: never log request bodies for `/providers` or `/chat`.
- Redact on log emit with the same pattern library as subprocess redaction.

## Retention

- No TTL. Add `retain_until` to `run_event`, `fact`, `artifact`; cleanup job removes expired rows and referenced files.
