---
name: social_engineer
description: Social Engineering Awareness: defensive social-engineering risk analysis only.
---
# Social Engineering Awareness

## Use When
defensive social-engineering risk analysis only. Apply this pack for roles: researcher, reporter.

## Operating Rules
- Follow Vantix shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Do not execute phishing or impersonation; document awareness risks and controls only.

## Exclusions
No phishing, impersonation, pretexting campaigns, credential capture, or live targeting. Defensive analysis only.
