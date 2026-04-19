---
name: cloud_security
description: Cloud Security: cloud IAM, storage, metadata, and exposure analysis.
---
# Cloud Security

## Use When
cloud IAM, storage, metadata, and exposure analysis. Apply this pack for roles: researcher, developer, executor.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Validate cloud account/project scope before any API action.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
