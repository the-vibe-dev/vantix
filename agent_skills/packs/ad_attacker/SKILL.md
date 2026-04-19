---
name: ad_attacker
description: Active Directory Security: AD enumeration and attack-path analysis.
---
# Active Directory Security

## Use When
AD enumeration and attack-path analysis. Apply this pack for roles: researcher, developer, executor.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Use read-first AD enumeration and approval gates for credential or lateral steps.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
