# Browser Agent Upgrade: Design

## Architecture
- New runtime service: `secops/services/browser_runtime.py`
  - Playwright/Chromium execution in isolated per-run context.
  - Policy-aware route traversal with max depth/page/request bounds.
  - Evidence capture: screenshots, DOM snapshots, route graph, form map, network summary, session summary.
  - Auth flow support from operator-provided config only.
  - Redaction of sensitive headers in captured network metadata.

- New workflow phase: `browser-assessment`
  - Inserted after `recon-sidecar`, before `cve-analysis`.
  - Produces structured browser observations before CVE/research planning.

- Browser planning adapter (inside execution phase)
  - Converts observations to:
    - `Fact(kind="route"|"form"|"api-endpoint"|"browser-session")`
    - `Fact(kind="vector")` with evidence-based scoring metadata
    - `Fact(kind="attack_chain")` candidate for planning bundle
    - `Artifact` records with provenance

## Safety and policy model
- New policy action kinds:
  - `browser_assessment`
  - `browser_auth`
  - `browser_high_noise`
  - `browser_sensitive_route`
- `browser_auth` and higher-risk browser actions require approval unless explicitly granted.
- Sensitive routes are blocked unless `allow_sensitive_routes=true` in run browser policy.
- Form submission remains policy-bound (`allow_form_submission`).

## Operator visibility
- Added browser-state API endpoint: `/api/v1/runs/{run_id}/browser-state`
- UI includes browser panel:
  - status/auth state
  - route and form counts
  - endpoint summary
  - blocked actions
  - quick open screenshot artifacts

## Reporting integration
- Report now includes a Browser Assessment section with:
  - auth state
  - pages/routes/forms discovered
  - browser artifact count
  - policy-gated browser actions
