---
name: cicd_redteam
description: CI/CD Red Team: pipeline, runner, artifact, and secret-flow review.
---
# CI/CD Red Team

## Use When
pipeline, runner, artifact, and secret-flow review. Apply this pack for roles: researcher, developer.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Analyze pipeline risks and propose safe validation of build/trust boundaries.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
