#!/usr/bin/env bash
# bugbounty-report.sh — HackerOne-format bug bounty report generator
#
# Converts a structured finding file into a submission-ready H1 report.
# Runs a pre-submission OOS checklist. Calculates CVSS score breakdown.
# Output is a markdown file ready to paste into the H1 platform.
#
# Usage:
#   bugbounty-report.sh --finding-file FINDING.md --program uber
#   bugbounty-report.sh --session SESSION_ID --program uber  # all findings
#   bugbounty-report.sh --session SESSION_ID --program uber --vuln ssrf

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BB_PROGRAMS="$CTF_ROOT/agent_ops/bugbounty/programs"
ARTIFACTS_ROOT="$CTF_ROOT/artifacts"

PROGRAM_ID=""
SESSION_ID=""
FINDING_FILE=""
VULN_FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --program|-p)      PROGRAM_ID="$2";    shift 2 ;;
    --finding-file|-f) FINDING_FILE="$2";  shift 2 ;;
    --session)         SESSION_ID="$2";    shift 2 ;;
    --vuln)            VULN_FILTER="$2";   shift 2 ;;
    -h|--help) grep '^#' "$0" | head -10 | sed 's/^# \?//'; exit 0 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

[[ -z "$PROGRAM_ID" ]] && { echo "[!] --program required"; exit 1; }

PROGRAM_YAML="$BB_PROGRAMS/$PROGRAM_ID/program.yaml"
[[ ! -f "$PROGRAM_YAML" ]] && { echo "[!] Program spec not found: $PROGRAM_YAML"; exit 1; }

ts() { date +%H:%M:%S; }
log() { echo "[$(ts)] $*"; }
ok()  { echo "[$(ts)] [+] $*"; }
warn(){ echo "[$(ts)] [!] $*"; }

# ── Collect finding files ─────────────────────────────────────────────────────
FINDINGS=()
if [[ -n "$FINDING_FILE" ]]; then
  [[ -f "$FINDING_FILE" ]] || { echo "[!] Finding file not found: $FINDING_FILE"; exit 1; }
  FINDINGS=("$FINDING_FILE")
elif [[ -n "$SESSION_ID" ]]; then
  FINDINGS_DIR="$ARTIFACTS_ROOT/bugbounty/$PROGRAM_ID/$SESSION_ID/findings"
  if [[ -n "$VULN_FILTER" ]]; then
    mapfile -t FINDINGS < <(find "$FINDINGS_DIR" -name "${VULN_FILTER}*.md" 2>/dev/null | sort || true)
  else
    mapfile -t FINDINGS < <(find "$FINDINGS_DIR" -name "*.md" 2>/dev/null | sort || true)
  fi
fi

[[ ${#FINDINGS[@]} -eq 0 ]] && { warn "No finding files found."; exit 0; }

# ── OOS checklist from program spec ──────────────────────────────────────────
mapfile -t OOS_VULNS < <(
  grep -A100 "out_of_scope_vuln_types:" "$PROGRAM_YAML" | \
    tail -n +2 | grep '    - ' | sed 's/    - //' | sed 's/"//g' || true
)

check_oos() {
  local vuln_type="$1"
  local vuln_lower="${vuln_type,,}"
  for oos in "${OOS_VULNS[@]}"; do
    if [[ "$vuln_lower" == *"${oos//_/ }"* ]] || [[ "$vuln_lower" == *"$oos"* ]]; then
      return 0  # IS out of scope
    fi
  done
  return 1  # not OOS
}

# ── CVSS 3.1 estimate ─────────────────────────────────────────────────────────
estimate_cvss() {
  local vuln_type="$1" severity="$2"
  case "${vuln_type,,}" in
    ssrf)
      echo "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
      echo "CVSS Base Score: ~8.6 (High) — adjust if auth required (set PR:L per program rules)"
      ;;
    idor)
      echo "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
      echo "CVSS Base Score: ~6.5 (Medium) — adjust scope/impact based on data sensitivity"
      ;;
    xss)
      echo "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
      echo "CVSS Base Score: ~6.1 (Medium) — stored XSS may be higher"
      ;;
    sqli)
      echo "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      echo "CVSS Base Score: ~9.8 (Critical)"
      ;;
    info_disclosure)
      echo "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
      echo "CVSS Base Score: ~5.3 (Medium) — varies by data sensitivity"
      ;;
    subdomain_takeover)
      echo "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"
      echo "CVSS Base Score: ~6.1 — Fixed reward: \$500"
      ;;
    auth_bypass)
      echo "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
      echo "CVSS Base Score: ~9.1 (Critical)"
      ;;
    *)
      echo "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
      echo "CVSS Base Score: ~6.5 — estimate; calculate at nvd.nist.gov/vuln-metrics/cvss/v3-calculator"
      ;;
  esac
}

# ── Impact bucket selector ────────────────────────────────────────────────────
get_impact_bucket() {
  local vuln_type="$1"
  case "${vuln_type,,}" in
    ssrf|info_disclosure) echo "Exposure of User Data / Safety" ;;
    idor)                 echo "Exposure of User Data / Unauthorized Requests on Behalf of User" ;;
    xss)                  echo "Unauthorized Requests on Behalf of User / Phishing" ;;
    sqli)                 echo "Exposure of User Data (Critical)" ;;
    auth_bypass)          echo "Unauthorized Requests on Behalf of User" ;;
    financial_fraud)      echo "Monetary Impact" ;;
    *)                    echo "Exposure of User Data" ;;
  esac
}

# ── Reward estimate ───────────────────────────────────────────────────────────
get_reward_range() {
  local severity="$1" vuln_type="$2"
  case "${severity,,}" in
    critical) echo "\$11,000–\$15,000 (avg \$13,368)" ;;
    high)     echo "\$4,000–\$11,000 (avg \$5,289)" ;;
    medium)   echo "\$500–\$2,500 (avg \$1,076)" ;;
    low)      echo "\$300–\$500 (avg \$300)" ;;
    *)
      case "${vuln_type,,}" in
        subdomain_takeover) echo "Fixed: \$500" ;;
        *) echo "Determined by security impact" ;;
      esac
      ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Generate report for each finding
# ─────────────────────────────────────────────────────────────────────────────
for finding_file in "${FINDINGS[@]}"; do
  log "Generating report for: $(basename "$finding_file")"

  # Parse finding metadata
  VULN_TYPE=$(grep "^- vuln_type:" "$finding_file" | awk '{print $3}' | tr -d '\r' || echo "unknown")
  TARGET=$(grep "^- target:" "$finding_file" | awk '{print $3}' | tr -d '\r' || echo "unknown")
  SEVERITY=$(grep "^- severity:" "$finding_file" | awk '{print $3}' | tr -d '\r' || echo "Medium")

  # OOS check
  if check_oos "$VULN_TYPE"; then
    warn "SKIPPING — $VULN_TYPE may be out-of-scope for $PROGRAM_ID"
    warn "Check the OOS list before submitting."
    echo ""
    continue
  fi

  CVSS_VECTOR=$(estimate_cvss "$VULN_TYPE" "$SEVERITY" | head -1)
  CVSS_NOTE=$(estimate_cvss "$VULN_TYPE" "$SEVERITY" | tail -1)
  IMPACT_BUCKET=$(get_impact_bucket "$VULN_TYPE")
  REWARD_RANGE=$(get_reward_range "$SEVERITY" "$VULN_TYPE")

  # Extract sections from finding
  EVIDENCE=$(awk '/^## Evidence/{found=1; next} found && /^## /{found=0} found{print}' "$finding_file" | head -30)
  IMPACT_DETAIL=$(awk '/^## Security Impact/{found=1; next} found && /^## /{found=0} found{print}' "$finding_file" | head -10)
  WHAT_WORKED=$(awk '/^## What worked/{found=1; next} found && /^## /{found=0} found{print}' "$finding_file" | head -5)

  # Output report
  REPORT_FILE="${finding_file%.md}_H1_REPORT.md"

  cat > "$REPORT_FILE" <<REPORT
# Bug Bounty Report: ${VULN_TYPE^^} in ${TARGET}

**Program**: ${PROGRAM_ID}
**Severity**: ${SEVERITY}
**Estimated bounty**: ${REWARD_RANGE}
**Impact bucket**: ${IMPACT_BUCKET}

---

## Summary

[1-2 sentence description — fill in: what the vulnerability is, where it exists, and what an attacker could do with it.]

Example: "A ${VULN_TYPE} vulnerability exists in ${TARGET}, allowing an unauthenticated attacker to [impact]. This could result in [consequence for users/Uber]."

---

## Steps to Reproduce

1. Navigate to: ${TARGET}
2. [Describe the parameter/feature being tested]
3. [Inject the test payload or manipulate the parameter]
4. [Observe the response confirming the vulnerability]

> **Note**: Testing was performed using personal test accounts only, at \`@wearehackerone.com\`.

---

## Proof of Concept

\`\`\`
${EVIDENCE}
\`\`\`

---

## Security Impact

${IMPACT_DETAIL}

### Multiplying factors
- [Scale: how many users could be affected?]
- [Data sensitivity: what type of data is exposed/manipulated?]
- [Severity of forged actions: what can an attacker do?]

### Mitigating factors
- [Authentication required? Rate limiting? User interaction needed?]

---

## CVSS 3.1

**Vector**: \`${CVSS_VECTOR}\`

${CVSS_NOTE}

Full calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

> Per Uber's policy: if authentication is required, set Privileges Required (PR) to **Low (L)**.

---

## Remediation

[Specific, actionable fix recommendation for this vulnerability type]

Common fixes for ${VULN_TYPE}:
$(case "${VULN_TYPE,,}" in
  ssrf)           echo "- Allowlist valid internal destinations; block 169.254.169.254 and RFC-1918 ranges"
                  echo "- Parse and validate URLs server-side before making requests"
                  echo "- Use a separate network zone for outbound request services" ;;
  idor)           echo "- Enforce object-level authorization checks on every data access"
                  echo "- Verify that the authenticated user owns the requested resource"
                  echo "- Use non-guessable identifiers (UUIDs) AND authorization checks" ;;
  xss)            echo "- Encode all user-controlled output in HTML context"
                  echo "- Implement Content-Security-Policy headers"
                  echo "- Use framework-level auto-escaping" ;;
  sqli)           echo "- Use parameterized queries / prepared statements exclusively"
                  echo "- Never concatenate user input into SQL strings" ;;
  info_disclosure)echo "- Disable debug endpoints in production"
                  echo "- Remove server version headers (X-Powered-By, Server)"
                  echo "- Ensure .env and config files are not web-accessible" ;;
  auth_bypass)    echo "- Validate all auth tokens server-side on each request"
                  echo "- Do not rely on client-side state for authorization decisions" ;;
  *)              echo "- Review the vulnerability class and apply defense-in-depth" ;;
esac)

---

## References

- [OWASP reference for ${VULN_TYPE}]
- CVSS 3.1: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
- Uber Bug Bounty Policy: https://hackerone.com/uber

---

*Generated by bugbounty-report.sh from: $(basename "$finding_file")*
REPORT

  ok "Report: $REPORT_FILE"

  # Pre-submission checklist
  echo ""
  echo "=== PRE-SUBMISSION CHECKLIST for $(basename "$REPORT_FILE") ==="
  echo "[?] Is the target in scope? (verify at: https://appsec-analysis.uber.com/public/bugbounty/ListDomains)"
  echo "[?] Does the report include a working PoC? (required — video-only PoC auto-closed)"
  echo "[?] Is the security impact clearly explained?"
  echo "[?] Did you use only your own test accounts?"
  echo "[?] Did you stop at minimal PoC (no unnecessary data extraction)?"
  echo "[?] Is the vulnerability reproducible with clear steps?"
  echo "[?] Is this a known duplicate? (search H1 for similar reports first)"
  check_oos "$VULN_TYPE" && echo "[!] WARNING: $VULN_TYPE may be out-of-scope — double-check OOS list" || echo "[OK] Vuln type not on OOS list"
  echo ""
done

ok "Report generation complete."
