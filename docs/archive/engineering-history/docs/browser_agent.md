# Browser Agent

Vantix includes a browser-native assessment phase (`browser-assessment`) that runs after recon and before CVE analysis.

## What it does
- Explores in-scope web routes in a real Chromium browser (Playwright).
- Captures:
  - route graph
  - form map
  - network request summary
  - DOM snapshots
  - screenshots
  - browser session summary
- Produces evidence-backed facts, vectors, and a planning attack-chain candidate.

## Workflow integration
- Phase: `browser-assessment`
- Role: `browser` (`Browser Analyst`)
- Inputs: run target + `config.browser` + optional `config.browser_auth`
- Outputs:
  - `Artifact` rows for browser evidence files
  - `Fact` rows for routes/forms/api/session
  - `Fact(kind="vector")` candidates
  - `Fact(kind="attack_chain")` candidate

## Run config (example)
```json
{
  "browser": {
    "enabled": true,
    "entry_url": "https://app.internal.local",
    "allowed_origins": ["https://app.internal.local"],
    "max_depth": 2,
    "max_pages": 25,
    "max_requests": 400,
    "allow_auth": false,
    "allow_form_submission": false,
    "allow_sensitive_routes": false,
    "capture_screenshots": true,
    "capture_storage": true
  }
}
```
