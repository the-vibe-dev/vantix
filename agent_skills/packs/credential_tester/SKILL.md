---
name: credential_tester
description: Credential Tester: credential validity analysis with lockout-safe policy.
---
# Credential Tester

## Use When
credential validity analysis with lockout-safe policy. Apply this pack for roles: researcher, executor.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
No stuffing/bruteforce by default; validate only explicitly authorized credentials.

## Exclusions
No brute force, password spraying, credential stuffing, lockout-risk testing, or raw secret storage by default.
