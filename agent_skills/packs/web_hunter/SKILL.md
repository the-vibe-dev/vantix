---
name: web_hunter
description: Web Hunter: web application discovery, fuzzing, and validation guidance.
---
# Web Hunter

## Use When
web application discovery, fuzzing, and validation guidance. Apply this pack for roles: recon, researcher, developer, executor.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Rate-limit web tests, start narrow, and preserve request/response evidence.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
