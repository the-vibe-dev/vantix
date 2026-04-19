---
name: vuln_scanner
description: Vulnerability Scanner: safe vulnerability scan planning and output triage.
---
# Vulnerability Scanner

## Use When
safe vulnerability scan planning and output triage. Apply this pack for roles: researcher, executor.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Use focused templates first; do not confuse scanner hits with confirmed findings.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
