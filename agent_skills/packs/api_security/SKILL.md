---
name: api_security
description: API Security: API discovery, authz, schema, and business-flow testing.
---
# API Security

## Use When
API discovery, authz, schema, and business-flow testing. Apply this pack for roles: researcher, developer, executor.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Map endpoints, auth boundaries, object ownership, and safe PoCs.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
