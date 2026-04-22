# Vantix Coverage Matrix

Public matrix of what Vantix exercises per mode. This exists so operators can
set expectations up-front: not every category runs in every mode, and the
depth of coverage varies deliberately with scope.

Mode abbreviations: **PT** = pentest, **BB** = bug bounty, **CTF** = capture
the flag. Depth legend: ● full · ◐ partial · ○ off-by-default.

| Category | PT | BB | CTF | Notes |
|---|---|---|---|---|
| Passive recon (DNS/WHOIS/cert) | ● | ● | ◐ | Deterministic; CTF skips WHOIS by default |
| Active port scan (nmap) | ● | ◐ | ● | BB throttles to scope host list |
| Service fingerprint + version | ● | ● | ● | Drives CVE correlation |
| Web crawl (authenticated) | ● | ● | ◐ | Requires `auth_profile` |
| CVE correlation | ● | ● | ○ | Off in CTF unless `--enable-cve` |
| Exploit validation (benign PoC) | ● | ◐ | ● | Gated by `exploit_validation` policy; BB defers to manual confirm |
| Browser evidence (screenshot/HAR) | ● | ● | ● | P1-5/6 — HAR at `artifacts/browser/network.har` |
| Session persistence | ● | ● | ◐ | Keyed by `(engagement_id, role_label)` |
| Attack-chain scoring | ● | ◐ | ● | P2-6 deterministic score (0–100) |
| Finding chain-of-custody | ● | ● | ● | P2-3 — promoted/reviewed/reviewer/disposition |
| Reviewer workflow | ● | ● | ○ | P2-5 — terminal dispositions latch |
| Provenance manifest | ● | ● | ● | P4-1 — `findings.provenance.json` with evidence sha256 |
| Signed attestation | ● | ● | ◐ | P4-3 — `scripts/sign-report.sh` (cosign) |
| Prometheus `/metrics` | ● | ● | ● | P3-8 — policy counters, lease gauge, heartbeat age |
| Runtime health | ● | ● | ● | P3-2 — `/runtime/health` |
| Run diff / compare | ● | ● | ● | P3-6 — `/runs/compare?a=&b=` |

## Scope boundaries

Vantix **does not** perform:

- Denial-of-service or availability attacks
- Exploit chains without an explicit validation gate
- Data exfiltration beyond what the engagement policy authorizes
- Supply-chain or third-party asset testing outside declared scope

Out-of-scope requests are rejected at policy-evaluation time; the decision is
logged as a `policy_decision` run event and surfaced in `/metrics`.

## Evidence integrity

Every finding carries:

1. A **fingerprint** (deterministic hash of kind + target + signal).
2. **Evidence IDs** resolving to `Artifact` rows with sha256 digests on disk.
3. A **reproduction script** hashed in the provenance manifest.
4. A **custody trio**: `promoted_at`, `reviewed_at`, `reviewer_user_id`.

Reports ship with `findings.provenance.json` and `report.attestation.json`.
Sign the attestation with `scripts/sign-report.sh` to let downstream consumers
verify the bundle without trusting the rendered Markdown/HTML.
