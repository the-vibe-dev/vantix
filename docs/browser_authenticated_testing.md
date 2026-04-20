# Browser Authenticated Testing

## Supported Inputs

Authenticated browser assessment is explicit. Vantix supports:

- operator-provided username/password selectors
- declared multi-step auth flows
- operator-provided session cookies
- role labels for session context tracking

Vantix does not support guessed credentials, password spraying, or brute-force auth workflows.

## Run Config Shape

```json
{
  "browser": {
    "entry_url": "https://target.example",
    "allowed_origins": ["https://target.example"],
    "allow_auth": true,
    "allow_form_submission": true
  },
  "browser_auth": {
    "login_url": "https://target.example/login",
    "username": "operator",
    "password": "redacted-at-rest",
    "username_selector": "#username",
    "password_selector": "#password",
    "submit_selector": "button[type='submit']",
    "role_label": "standard-user",
    "steps": [
      {"action": "goto", "url": "https://target.example/login"},
      {"action": "fill", "selector": "#username", "value": "${username}"},
      {"action": "fill", "selector": "#password", "value": "${password}"},
      {"action": "click", "selector": "button[type='submit']"},
      {"action": "wait", "ms": 1200}
    ],
    "session_cookies": [
      {"name": "sessionid", "value": "redacted", "domain": "target.example", "path": "/"}
    ]
  }
}
```

## Recorded Outcomes

The browser phase records:

- `not_attempted`
- `partial`
- `success`
- `failed`

It also captures auth transition evidence and DOM/state deltas so the operator can see what changed before any escalation.

## Secret Handling

- request headers such as `Authorization`, `Cookie`, `Set-Cookie`, and `X-API-Key` are redacted in browser network summaries
- browser docs and reports store state summaries, not credential values
- operators should still keep `.env`, runtime storage, and exported artifacts scoped appropriately
