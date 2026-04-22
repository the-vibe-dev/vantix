# Vantix Positioning

## One-liner

Vantix is an operator-facing pentest platform where every finding carries a
verifiable chain of evidence, a reproduction script, and a signed attestation
— so the report is the artifact, not the starting point.

## Why another pentest tool

The market splits into two camps:

- **Scanners** (Nessus/Nuclei/Burp scanner) — fast, shallow, no chain.
- **Agentic frameworks** (Shannon, PentAGI, Strix) — deep, exploratory, but
  the operator has to reconstruct what happened from logs.

Vantix is positioned in between: agentic execution with a runtime that
writes its own audit trail as it goes. A finding is not credible until it
links to evidence artifacts, a reviewer disposition, and a deterministic
reproduction.

## Differentiators

| Axis | Scanners | Agentic frameworks | **Vantix** |
|---|---|---|---|
| Time-to-report | minutes | hours | **minutes, report-ready** |
| Per-finding evidence chain | ✗ | partial | **✓ (sha256 + reviewer)** |
| Deterministic reproduction | ✗ | ✗ | **✓ (script in manifest)** |
| Signed attestation | ✗ | ✗ | **✓ (cosign)** |
| Policy-gated exploit validation | n/a | inconsistent | **✓** |
| Operator review UI | ✗ | ✗ | **✓** |

## Demo flow (≤ 8 minutes)

1. **Launch** — `scripts/vantix-run.py --quick --target https://demo.target`
   kicks off a quick-scan profile. (Or click *Quick Scan* in the UI.)
2. **Live triage** — the Results panel streams findings; dedup + suppression
   banners show the gate working. Attack Vectors panel colors hypotheses
   vs. validated vs. refuted.
3. **Evidence drawer** — click any finding → `FindingEvidenceDrawer` opens
   with the custody trio, evidence artifact links, and the reproduction
   script with a *Replay* clipboard action.
4. **Review** — click *Confirm*. Disposition latches; the reviewer identity
   is stamped from the session.
5. **Runtime health** — `RuntimeHealthPanel` shows worker leases, heartbeat
   ages, and stale candidates. `/metrics` is scraped by Prometheus.
6. **Compare** — open a prior run; `RunCompareDrawer` diffs findings,
   phase durations, and vector counts.
7. **Ship** — report renders to Markdown + HTML; `findings.provenance.json`
   and `report.attestation.json` drop alongside. Run `scripts/sign-report.sh`
   to attach a cosign signature.

## Target operators

- **Internal red teams** that need to hand off evidence to blue teams
  without rebuilding context.
- **Bug-bounty hunters** who want a deterministic repro script attached to
  every submission.
- **Consultancies** producing client deliverables that have to survive
  legal review.

## Non-goals

- We do not replace a human operator for novel exploit research.
- We do not ship zero-day. Exploit validation is benign-PoC only, policy-gated.
- We are not a SIEM or a SOC tool — Vantix generates evidence, it does not
  ingest alerts.
