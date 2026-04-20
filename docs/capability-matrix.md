# Capability Matrix

This matrix is intentionally conservative. Vantix is an operator control plane for authorized assessment work, not a fully automatic exploit bot.

| Category | Supported | Depth | Notes |
| --- | --- | --- | --- |
| Durable multi-phase workflow orchestration | Yes | High | DB-backed phase state, leases, retries, checkpoints. |
| Operator approvals and policy gates | Yes | High | Approval queue, policy decisions, scope gates, bounded execution. |
| Evidence-first reporting | Yes | High | Facts, artifacts, findings, provenance-aware reports. |
| Browser-native authorized web assessment | Yes | Medium | Route discovery, forms, network summaries, screenshots, session state. |
| Browser-authenticated assessment | Yes | Medium | Operator-provided auth only; approval-gated; bounded flows. |
| Black-box recon orchestration | Yes | Medium | Low-noise recon, CVE/intel enrichment, vector generation. |
| White-box source intake | Yes | Medium | Local path, GitHub URL, staged upload intake with source analysis hooks. |
| Attack-chain modelling | Yes | Medium | Candidate chains, vector selection, finding promotion. |
| Multi-worker recovery | Partial | Medium | Lease-based claims and reclaim are present; wider concurrency hardening is still active work. |
| Replay mode | Partial | Medium | Timeline, phase history, and replay snapshot views exist; full what-if simulation is not complete yet. |
| Plugin ecosystem | Partial | Low | Internal extension seams exist; external plugin UX is not finalized. |

## Current strengths

- Operator-visible workflow state
- Policy and approval control
- Evidence capture and report generation
- Browser evidence as first-class assessment output
- Local-first runtime and storage model

## Current gaps

- Deeper browser auth/session modeling
- More robust multi-worker hardening and scavenging visibility
- Richer replay and what-if operator tooling
- More polished public trust assets and sanitized sample reports
