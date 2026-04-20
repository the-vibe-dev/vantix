# Browser Policies

## Policy Controls

Browser assessment respects run-scoped browser policy fields under `config.browser`:

- `entry_url`
- `allowed_origins`
- `max_depth`
- `max_pages`
- `max_requests`
- `allow_auth`
- `capture_screenshots`
- `capture_storage`
- `allow_form_submission`
- `allow_sensitive_routes`
- `high_noise`

## Approval Gates

The workflow/policy layer can block or require approval for:

- browser assessment itself
- authenticated session use
- form submission
- sensitive route interaction
- any follow-on validation that goes beyond bounded evidence capture

When approval is required, the run is blocked cleanly and the operator must approve or reject before the phase resumes.

## Default Discipline

- keep `allowed_origins` narrow
- keep `allow_form_submission` off unless the target and method require it
- treat `allow_sensitive_routes` as a privileged setting
- use auth only with operator-provided credentials or declared session cookies

## Example

```json
{
  "browser": {
    "entry_url": "https://target.example",
    "allowed_origins": ["https://target.example"],
    "max_depth": 2,
    "max_pages": 25,
    "max_requests": 400,
    "allow_auth": true,
    "capture_screenshots": true,
    "capture_storage": true,
    "allow_form_submission": false,
    "allow_sensitive_routes": false
  }
}
```
