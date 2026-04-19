# Vantix Providers

Vantix is Codex-first. The default runtime uses the local Codex CLI and its existing OAuth/session state to avoid unintended provider API spend. API providers are optional configuration records for future model routing and controlled experiments.

## Environment

| Variable | Purpose |
| --- | --- |
| `VANTIX_SECRET_KEY` | Preferred encryption key for stored provider secrets. |
| `SECOPS_SECRET_KEY` | Backward-compatible fallback encryption key. |
| `SECOPS_CODEX_BIN` | Codex binary path/name. Defaults to `codex`. |
| `SECOPS_DEFAULT_MODEL` | Default Codex model label used by generated prompts. |
| `SECOPS_DEFAULT_REASONING_EFFORT` | Default Codex reasoning effort label. |

If neither `VANTIX_SECRET_KEY` nor `SECOPS_SECRET_KEY` is set, provider records can still be saved without a secret. Any attempt to store a provider secret is rejected.

Generate a local secret key:

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

Add it to `.env`:

```bash
VANTIX_SECRET_KEY=replace-with-generated-local-secret
```

Do not commit `.env` or any provider key.

## API

Provider routes require the normal bearer token when `SECOPS_API_TOKEN` is configured.

```bash
curl -H "Authorization: Bearer $SECOPS_API_TOKEN" http://127.0.0.1:8787/api/v1/providers
```

Create or update a provider record:

```bash
curl -X POST http://127.0.0.1:8787/api/v1/providers \
  -H "Authorization: Bearer $SECOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Local Ollama",
    "provider_type": "ollama",
    "base_url": "http://127.0.0.1:11434",
    "default_model": "qwen2.5-coder:14b",
    "enabled": false
  }'
```

Supported `provider_type` values:

- `openai`
- `anthropic`
- `gemini`
- `ollama`
- `bedrock`
- `deepseek`
- `glm`
- `kimi`
- `qwen`
- `openrouter`
- `custom`

Responses expose `has_key` but never return raw or decrypted secrets.

## UI

The Runtime Settings panel stores the UI API token in browser local storage and can create provider records. This is operator convenience only; it is not full multi-user auth.

## Current Limits

- Provider `test` is a dry-run configuration check in v1.
- Runs do not silently switch to API providers.
- Codex remains the default execution mechanism.
- Live model-provider routing should be added only with explicit run-level selection and cost controls.
