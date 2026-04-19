---
name: bug_bounty
description: Bug Bounty: program-scope triage and report-quality validation.
---
# Bug Bounty

## Use When
program-scope triage and report-quality validation. Apply this pack for roles: orchestrator, researcher, reporter.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Keep testing in program scope and optimize for reproducible evidence.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
