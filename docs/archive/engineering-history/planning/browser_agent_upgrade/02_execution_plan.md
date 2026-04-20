# Browser Agent Upgrade: Execution Plan

## 1) Runtime and workflow integration
1. Add `BrowserRuntimeService` with Playwright-backed traversal and artifact capture.
2. Add `browser-assessment` phase to workflow phase sequence.
3. Wire execution handler and run-service default task seed for the new phase.
4. Extend Vantix specialist mapping and agent roster with `browser` role.

## 2) Policy and approvals
1. Introduce browser action kinds in policy service.
2. Require approval for auth/sensitive/high-noise browser behaviors.
3. Persist approval metadata for browser context and target.

## 3) Evidence and planning outputs
1. Persist browser artifacts (`dom-snapshot`, `screenshot`, `route-discovery`, `form-map`, `network-summary`, `browser-session-summary`).
2. Generate route/form/api/session facts.
3. Generate scored browser vectors and a browser-derived attack chain candidate.
4. Emit chat/event summaries for traceability.

## 4) API and UI visibility
1. Add `/runs/{id}/browser-state` endpoint.
2. Add frontend API type + fetch method.
3. Add browser panel to Intel view and include browser role in Agent Team.

## 5) Reporting and docs
1. Add browser section and provenance in `ReportingService`.
2. Add docs for browser agent behavior, policies, artifacts, and authenticated testing.
3. Add planning docs for current state, design, and plan.

## 6) Tests
1. Runtime parser/safety helper tests.
2. Browser phase integration test with mocked runtime outputs.
3. Policy-gated auth flow approval test.
4. Browser-state API payload compatibility test.
