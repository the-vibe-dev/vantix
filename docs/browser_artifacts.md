# Browser Artifacts

## Artifact Kinds

Browser assessment can persist these artifact kinds under the run workspace:

- `browser-session-summary`
- `browser-auth-state`
- `browser-js-signals`
- `route-discovery`
- `form-map`
- `network-summary`
- `dom-snapshot`
- `screenshot`

## What Each Artifact Contains

`browser-session-summary`
- entry/current URL
- authenticated state
- blocked actions
- page count
- auth transition count
- DOM diff count
- final storage summary
- effective browser policy summary

`browser-auth-state`
- auth transition stages
- auth outcome status
- DOM/state deltas across auth and navigation

`browser-js-signals`
- client-side framework/config/debug hints
- hidden/admin/debug route hints
- page-level DOM summary

`route-discovery`
- visited URLs
- route edges

`form-map`
- per-page forms
- field metadata
- auth-like form markers

`network-summary`
- request counts
- method/host breakdown
- endpoint summaries

`dom-snapshot`
- page title
- links
- forms
- scripts
- storage summary
- DOM summary
- JS signals
- route hints

## Provenance

Artifacts are attached to the run and tagged with the browser phase. Browser-derived facts and vectors should point back to these artifacts through metadata and report provenance rather than freeform claims.
