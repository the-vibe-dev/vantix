---
name: scope_guard
description: Scope Guard: shared safety and scope enforcement.
---
# Scope Guard

## Use When
shared safety and scope enforcement. Apply this pack for roles: orchestrator, recon, researcher, developer, executor, reporter.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Requires scope validation before execution-capable work.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
