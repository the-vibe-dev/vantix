---
name: poc_validator
description: PoC Validator: non-destructive vulnerability confirmation.
---
# PoC Validator

## Use When
non-destructive vulnerability confirmation. Apply this pack for roles: developer, executor, researcher.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Use canaries/read-only checks; kill false positives before reporting.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
