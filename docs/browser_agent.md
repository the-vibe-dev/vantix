# Browser Agent

## Purpose

Vantix browser assessment is an evidence-first, policy-gated web application assessment phase for authorized targets. It uses a local Playwright Chromium runtime to collect operator-reviewable evidence and convert that evidence into facts, vectors, and planning candidates.

## What It Produces

- route discovery and navigation edges
- form maps and auth-like form detection
- network request summaries and likely API endpoints
- DOM snapshots and screenshots
- browser session summaries
- auth/session transition records
- DOM/state deltas between auth/navigation states
- client-side signals such as app-config, debug, GraphQL, and feature-flag indicators
- hidden/admin/debug route hints

## Workflow Fit

Browser assessment runs as the `browser-assessment` phase. Its outputs feed:

- `Fact` records for routes, forms, browser sessions, API endpoints, route hints, JS signals, and auth transitions
- browser-derived `Vector` candidates for auth boundaries, state transitions, client trust issues, admin/debug surfaces, and API mismatch review
- attack-chain planning candidates
- browser sections in the operator UI and final report

## Runtime Requirements

- Python package: `playwright`
- Browser runtime: Chromium installed with `.venv/bin/python -m playwright install chromium`
- Browser policy and auth config under run config

## Safety Model

- in-scope origins only
- depth/page/request limits
- explicit auth enablement
- policy-gated auth submission and sensitive route access
- no credential guessing or brute force
- no uncontrolled form submission
- no stealth/evasion behavior

## Key Files

- `secops/services/browser_runtime.py`
- `secops/services/execution.py`
- `secops/routers/runs.py`
- `frontend/src/App.tsx`
- `tests/test_browser_agent.py`
