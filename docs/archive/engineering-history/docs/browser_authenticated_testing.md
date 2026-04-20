# Browser Authenticated Testing

Authenticated browser testing is supported only with operator-provided credentials and explicit policy approval.

## Requirements
- `config.browser.allow_auth = true`
- `config.browser_auth` present with declared login flow fields
- approval for `browser_auth` action kind

## Example
```json
{
  "browser": {
    "enabled": true,
    "entry_url": "https://app.internal.local",
    "allowed_origins": ["https://app.internal.local"],
    "allow_auth": true,
    "allow_form_submission": true
  },
  "browser_auth": {
    "login_url": "https://app.internal.local/login",
    "username": "operator-user",
    "password": "operator-secret",
    "username_selector": "input[name='username']",
    "password_selector": "input[type='password']",
    "submit_selector": "button[type='submit']"
  }
}
```

## Safety and handling
- No brute force or credential attacks.
- Sensitive values are redacted from network metadata (`Authorization`, cookies, API keys).
- Reports and artifacts store session state summaries, not raw secrets.
