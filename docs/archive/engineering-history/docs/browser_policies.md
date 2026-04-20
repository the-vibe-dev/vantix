# Browser Policies

Browser actions are policy-evaluated just like other execution actions.

## Action kinds
- `browser_assessment`
- `browser_auth`
- `browser_high_noise`
- `browser_sensitive_route`

## Default behavior
- `browser_assessment`: allowed with audit unless disabled in run config.
- `browser_auth`: requires operator approval/grant.
- `browser_high_noise`: requires operator approval/grant.
- `browser_sensitive_route`: requires operator approval/grant.

## Approval gates
Use approvals to allow:
- authenticated session usage
- sensitive route validation
- high-noise browser traversal
- state-changing form submission in risky contexts

These approvals are recorded in the run event/message timeline.
