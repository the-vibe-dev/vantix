# Browser Artifacts

Browser assessment writes run-scoped artifacts under:
- `${SECOPS_RUNTIME_ROOT}/runs/<workspace_id>/artifacts/browser/`

## Artifact kinds
- `screenshot`
- `dom-snapshot`
- `route-discovery`
- `form-map`
- `network-summary`
- `browser-session-summary`

## Provenance
Each artifact row includes:
- `run_id`
- artifact `kind` and `path`
- phase metadata (`browser-assessment`)
- capture timestamp and agent session metadata

## API visibility
- Use `GET /api/v1/runs/{run_id}/browser-state` for aggregated browser state and artifact pointers.
