#!/usr/bin/env bash
# bugbounty-recon.sh — Bug bounty reconnaissance pipeline
#
# Runs passive → active asset discovery, fingerprinting, and quick-win checks
# on an authorized bug bounty target. Every discovered host is scope-checked
# before any active probe.
#
# Usage:
#   bugbounty-recon.sh --program uber [--session SESSION_ID]
#   bugbounty-recon.sh --program uber --target-override rider.uber.com
#   bugbounty-recon.sh --program uber --phase discovery|fingerprint|quickwins|all
#   bugbounty-recon.sh --program uber --dry-run   # scope check only

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SCOPE_CHECK="$CTF_ROOT/scripts/bugbounty-scope.sh"
LEARN_ENGINE="$CTF_ROOT/scripts/learn_engine.py"
BB_PROGRAMS="$CTF_ROOT/agent_ops/bugbounty/programs"
ARTIFACTS_ROOT="$CTF_ROOT/artifacts"
GO_BIN="${HOME}/go/bin"
export PATH="$PATH:$GO_BIN:${HOME}/.local/bin"

PROGRAM_ID=""
SESSION_ID=""
TARGET_OVERRIDE=""
PHASE="all"
DRY_RUN=false
PASSIVE_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --program|-p)        PROGRAM_ID="$2";       shift 2 ;;
    --session)           SESSION_ID="$2";        shift 2 ;;
    --target-override)   TARGET_OVERRIDE="$2";   shift 2 ;;
    --phase)             PHASE="$2";             shift 2 ;;
    --dry-run)           DRY_RUN=true;           shift ;;
    --passive-only)      PASSIVE_ONLY=true;      shift ;;
    -h|--help) grep '^#' "$0" | head -12 | sed 's/^# \?//'; exit 0 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

[[ -z "$PROGRAM_ID" ]] && { echo "[!] --program required"; exit 1; }

PROGRAM_YAML="$BB_PROGRAMS/$PROGRAM_ID/program.yaml"
[[ ! -f "$PROGRAM_YAML" ]] && { echo "[!] Program spec not found: $PROGRAM_YAML"; exit 1; }

[[ -z "$SESSION_ID" ]] && SESSION_ID="recon-$(date +%Y%m%d-%H%M%S)"
TS=$(date +%Y%m%d-%H%M%S)
OUT_DIR="$ARTIFACTS_ROOT/bugbounty/$PROGRAM_ID/$SESSION_ID/recon"
mkdir -p "$OUT_DIR"

SUMMARY="$OUT_DIR/recon_summary.md"
LIVE_HOSTS="$OUT_DIR/live_hosts.txt"
ALL_URLS="$OUT_DIR/all_urls.txt"
JS_FILES="$OUT_DIR/js_files.txt"
PARAMS="$OUT_DIR/params.txt"
FINDINGS="$OUT_DIR/quick_wins.md"

ts()   { date +%H:%M:%S; }
log()  { echo "[$(ts)] $*"; }
ok()   { echo "[$(ts)] [+] $*"; }
warn() { echo "[$(ts)] [!] $*"; }

# ── YAML helpers ──────────────────────────────────────────────────────────────
yaml_list() {
  grep -A100 "^  ${1}:" "$PROGRAM_YAML" 2>/dev/null | \
    tail -n +2 | grep '^    - ' | sed 's/^    - //' | sed 's/"//g' | sed "s/'//g" | \
    grep -v '^[[:space:]]*$' || true
}

# ── Scope gate wrapper ────────────────────────────────────────────────────────
scope_ok() {
  local target="$1"
  local result
  result=$("$SCOPE_CHECK" --target "$target" --program "$PROGRAM_ID" --quiet 2>/dev/null || echo "OUT_OF_SCOPE")
  [[ "$result" == "IN_SCOPE" ]]
}

# ── Get wildcard domains from program spec ────────────────────────────────────
mapfile -t WILDCARDS < <(yaml_list "wildcard_in_scope")
RECON_DOMAINS_API=$(grep "domains:" "$PROGRAM_YAML" | grep "appsec-analysis\|ListDomains" | awk '{print $2}' | tr -d '"' | head -1 || true)

{
  echo "# Recon Summary: $PROGRAM_ID"
  echo ""
  echo "- session: $SESSION_ID"
  echo "- program: $PROGRAM_ID"
  echo "- ts: $TS"
  echo "- phase: $PHASE"
  echo ""
} > "$SUMMARY"

# ── Build target list ─────────────────────────────────────────────────────────
TARGET_DOMAINS=()
if [[ -n "$TARGET_OVERRIDE" ]]; then
  TARGET_DOMAINS=("$TARGET_OVERRIDE")
  log "Target override: $TARGET_OVERRIDE"
elif [[ -n "$RECON_DOMAINS_API" ]]; then
  log "Fetching domain list from asset recon API..."
  DOMAINS_JSON=$(curl -sk --max-time 30 "$RECON_DOMAINS_API?offset=0&limit=500" 2>/dev/null || echo "[]")
  mapfile -t TARGET_DOMAINS < <(
    echo "$DOMAINS_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    seen = set()
    for item in (data if isinstance(data, list) else []):
        d = item if isinstance(item, str) else item.get('domain', item.get('hostname', ''))
        d = d.strip().lower().lstrip('*.')
        if d and d not in seen:
            seen.add(d)
            print(d)
except: pass
" 2>/dev/null || true)
  log "Got ${#TARGET_DOMAINS[@]} domains from API"
else
  # Fall back to wildcard base domains
  for wc in "${WILDCARDS[@]}"; do
    TARGET_DOMAINS+=("${wc#\*.}")
  done
  log "Using ${#TARGET_DOMAINS[@]} wildcard base domains"
fi

echo "- target_domains: ${#TARGET_DOMAINS[@]}" >> "$SUMMARY"
printf '%s\n' "${TARGET_DOMAINS[@]}" > "$OUT_DIR/target_domains.txt"

$DRY_RUN && { log "Dry run — scope checks only, no active probing"; }

# ════════════════════════════════════════════════════════════════════════════
# Phase 1: Subdomain discovery
# ════════════════════════════════════════════════════════════════════════════
if [[ "$PHASE" == "all" || "$PHASE" == "discovery" ]]; then
  log "=== Phase 1: Subdomain Discovery ==="
  SUBDOMAIN_FILE="$OUT_DIR/subdomains_raw.txt"
  > "$SUBDOMAIN_FILE"

  for domain in "${TARGET_DOMAINS[@]}"; do
    log "Enumerating: $domain"

    # Subfinder (passive)
    if command -v subfinder &>/dev/null; then
      subfinder -d "$domain" -silent 2>/dev/null >> "$SUBDOMAIN_FILE" || true
    fi

    # Amass passive
    if command -v amass &>/dev/null && ! $DRY_RUN; then
      timeout 120 amass enum -passive -d "$domain" -silent 2>/dev/null >> "$SUBDOMAIN_FILE" || true
    fi

    # Certificate transparency via crt.sh
    if ! $DRY_RUN; then
      curl -sk --max-time 15 "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null | \
        python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    seen = set()
    for cert in data:
        for name in cert.get('name_value','').split('\n'):
            name = name.strip().lower().lstrip('*.')
            if name and name not in seen and '${domain}' in name:
                seen.add(name)
                print(name)
except: pass
" 2>/dev/null >> "$SUBDOMAIN_FILE" || true
    fi
  done

  # Deduplicate
  sort -u "$SUBDOMAIN_FILE" > "$OUT_DIR/subdomains.txt"
  SUBDOMAIN_COUNT=$(wc -l < "$OUT_DIR/subdomains.txt")
  ok "Subdomains found: $SUBDOMAIN_COUNT"

  # ── Probe for live hosts ──────────────────────────────────────────────────
  if ! $DRY_RUN && ! $PASSIVE_ONLY; then
    log "Probing live hosts (httpx)..."
    > "$LIVE_HOSTS"
    if command -v httpx &>/dev/null; then
      # scope-check each subdomain first
      while IFS= read -r subdomain; do
        if scope_ok "$subdomain"; then
          echo "$subdomain"
        else
          warn "OOS skip: $subdomain"
        fi
      done < "$OUT_DIR/subdomains.txt" | \
        httpx -silent -title -tech-detect -status-code -follow-redirects \
              -threads 50 -timeout 10 2>/dev/null > "$LIVE_HOSTS" || true
    else
      # httpx not available — use curl probing
      while IFS= read -r subdomain; do
        scope_ok "$subdomain" || continue
        for scheme in https http; do
          status=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$scheme://$subdomain/" 2>/dev/null || echo "000")
          if [[ "$status" != "000" ]]; then
            echo "$scheme://$subdomain/ [$status]" >> "$LIVE_HOSTS"
            break
          fi
        done
      done < "$OUT_DIR/subdomains.txt"
    fi
    LIVE_COUNT=$(wc -l < "$LIVE_HOSTS")
    ok "Live hosts: $LIVE_COUNT"
    echo "## Discovery" >> "$SUMMARY"
    echo "- subdomains_raw: $SUBDOMAIN_COUNT" >> "$SUMMARY"
    echo "- live_hosts: $LIVE_COUNT" >> "$SUMMARY"
    echo "" >> "$SUMMARY"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════
# Phase 2: Fingerprinting
# ════════════════════════════════════════════════════════════════════════════
if [[ "$PHASE" == "all" || "$PHASE" == "fingerprint" ]] && ! $DRY_RUN && ! $PASSIVE_ONLY; then
  log "=== Phase 2: Fingerprinting ==="

  FINGERPRINT_DIR="$OUT_DIR/../fingerprint"
  mkdir -p "$FINGERPRINT_DIR"

  # Tech fingerprinting
  if [[ -f "$LIVE_HOSTS" ]]; then
    log "Fingerprinting technologies..."
    if command -v whatweb &>/dev/null; then
      # Extract URLs from live_hosts
      grep -oE 'https?://[^ ]+' "$LIVE_HOSTS" | head -50 | while read -r url; do
        base_domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||')
        scope_ok "$base_domain" || continue
        whatweb --log-brief="$FINGERPRINT_DIR/${base_domain//\//_}_tech.txt" "$url" 2>/dev/null || true
      done
    fi
  fi

  # JavaScript file collection (katana)
  log "Collecting JavaScript files..."
  > "$JS_FILES"
  if command -v katana &>/dev/null && [[ -f "$LIVE_HOSTS" ]]; then
    grep -oE 'https?://[^ ]+' "$LIVE_HOSTS" | head -20 | while read -r url; do
      base_domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||')
      scope_ok "$base_domain" || continue
      timeout 60 katana -u "$url" -silent -js-crawl -depth 3 2>/dev/null | \
        grep '\.js' >> "$JS_FILES" || true
    done
    sort -u "$JS_FILES" -o "$JS_FILES"
    ok "JS files: $(wc -l < "$JS_FILES")"
  fi

  # URL collection (gau/waybackurls)
  log "Collecting historical URLs..."
  > "$ALL_URLS"
  for domain in "${TARGET_DOMAINS[@]}"; do
    scope_ok "$domain" || continue
    if command -v gau &>/dev/null; then
      timeout 60 gau --subs --threads 5 "$domain" 2>/dev/null >> "$ALL_URLS" || true
    elif command -v waybackurls &>/dev/null; then
      echo "$domain" | timeout 60 waybackurls 2>/dev/null >> "$ALL_URLS" || true
    fi
  done
  sort -u "$ALL_URLS" -o "$ALL_URLS"
  ok "Historical URLs: $(wc -l < "$ALL_URLS")"

  # Parameter discovery (arjun on interesting endpoints)
  if command -v arjun &>/dev/null && [[ -s "$ALL_URLS" ]]; then
    log "Parameter discovery (arjun on top endpoints)..."
    # Focus on endpoints likely to have params
    grep -E '\.(php|asp|aspx|jsp|do|action)(\?|$)|/api/|/v[0-9]+/' "$ALL_URLS" | \
      head -20 > "$OUT_DIR/param_targets.txt" || true
    if [[ -s "$OUT_DIR/param_targets.txt" ]]; then
      arjun -i "$OUT_DIR/param_targets.txt" -oT "$PARAMS" -t 10 -q 2>/dev/null || true
      ok "Parameters: $(wc -l < "$PARAMS" 2>/dev/null || echo 0)"
    fi
  fi

  {
    echo "## Fingerprinting"
    echo "- js_files: $(wc -l < "$JS_FILES" 2>/dev/null || echo 0)"
    echo "- historical_urls: $(wc -l < "$ALL_URLS" 2>/dev/null || echo 0)"
    echo "- tech_fingerprints: $FINGERPRINT_DIR"
    echo ""
  } >> "$SUMMARY"
fi

# ════════════════════════════════════════════════════════════════════════════
# Phase 3: Quick wins
# ════════════════════════════════════════════════════════════════════════════
if [[ "$PHASE" == "all" || "$PHASE" == "quickwins" ]] && ! $DRY_RUN; then
  log "=== Phase 3: Quick wins ==="

  {
    echo "# Quick Win Findings"
    echo ""
    echo "- session: $SESSION_ID"
    echo "- ts: $TS"
    echo ""
  } > "$FINDINGS"

  # ── Subdomain takeover check (Uber pays fixed $500) ──────────────────────
  log "Checking subdomain takeover potential..."
  TAKEOVER_HITS=0
  # Common dangling CNAME providers
  DANGLING_PATTERNS=(
    "s3.amazonaws.com:S3 bucket"
    "azurewebsites.net:Azure"
    "cloudapp.net:Azure"
    "github.io:GitHub Pages"
    "bitbucket.io:Bitbucket"
    "heroku.com:Heroku"
    "shopify.com:Shopify"
    "fastly.net:Fastly"
    "pantheon.io:Pantheon"
    "squarespace.com:Squarespace"
    "statuspage.io:StatusPage"
    "desk.com:Zendesk Desk"
    "zendesk.com:Zendesk"
    "readme.io:ReadMe"
    "surge.sh:Surge"
  )

  if [[ -f "$OUT_DIR/subdomains.txt" ]]; then
    while IFS= read -r subdomain; do
      scope_ok "$subdomain" || continue
      cname=$(dig +short CNAME "$subdomain" 2>/dev/null | head -1 || true)
      [[ -z "$cname" ]] && continue
      for pattern_entry in "${DANGLING_PATTERNS[@]}"; do
        provider_domain="${pattern_entry%%:*}"
        provider_name="${pattern_entry##*:}"
        if echo "$cname" | grep -qi "$provider_domain"; then
          # Check if the CNAME target actually resolves
          if ! curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "http://$subdomain" 2>/dev/null | grep -qE "^[23]"; then
            warn "POTENTIAL SUBDOMAIN TAKEOVER: $subdomain → $cname ($provider_name)"
            {
              echo "## POTENTIAL SUBDOMAIN TAKEOVER — \$500 fixed reward"
              echo ""
              echo "- subdomain: $subdomain"
              echo "- cname_target: $cname"
              echo "- provider: $provider_name"
              echo "- status: CNAME resolves to unclaimed $provider_name resource"
              echo ""
              echo "**Next step:** Claim the $provider_name resource and leave a non-offensive message (your HackerOne username)."
              echo ""
            } >> "$FINDINGS"
            TAKEOVER_HITS=$((TAKEOVER_HITS + 1))
          fi
        fi
      done
    done < "$OUT_DIR/subdomains.txt"
    ok "Subdomain takeover checks done. Hits: $TAKEOVER_HITS"
  fi

  # ── Secret scanning in JS files ───────────────────────────────────────────
  if [[ -s "$JS_FILES" ]] && command -v trufflehog &>/dev/null; then
    log "Scanning JS files for secrets (trufflehog)..."
    SECRET_HITS="$OUT_DIR/secrets_raw.txt"
    while IFS= read -r js_url; do
      base_domain=$(echo "$js_url" | sed 's|https\?://||' | sed 's|/.*||')
      scope_ok "$base_domain" || continue
      trufflehog --only-verified "$js_url" 2>/dev/null >> "$SECRET_HITS" || true
    done < "$JS_FILES"
    if [[ -s "$SECRET_HITS" ]]; then
      warn "Secrets found! See: $SECRET_HITS"
      {
        echo "## Credential/Secret Exposure"
        echo ""
        echo "Trufflehog found verified secrets in JavaScript files."
        echo "See: $SECRET_HITS"
        echo ""
      } >> "$FINDINGS"
    fi
  fi

  # ── Exposed .git directories ──────────────────────────────────────────────
  log "Checking for exposed .git directories..."
  if [[ -f "$LIVE_HOSTS" ]]; then
    grep -oE 'https?://[^ ]+' "$LIVE_HOSTS" | head -30 | while read -r url; do
      base_domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||')
      scope_ok "$base_domain" || continue
      status=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "${url}/.git/HEAD" 2>/dev/null || echo "000")
      if [[ "$status" == "200" ]]; then
        warn "Exposed .git: $url/.git/HEAD"
        {
          echo "## Exposed .git Directory"
          echo ""
          echo "- url: $url/.git/HEAD"
          echo "- status: $status"
          echo "- impact: Source code disclosure (High)"
          echo ""
        } >> "$FINDINGS"
      fi
    done
  fi

  # ── Third-party info disclosures (Trello, Google Docs) ────────────────────
  log "Checking for third-party info disclosures..."
  COMPANY_NAME=$(grep "program_id:" "$PROGRAM_YAML" | awk '{print $2}')
  for service_url in \
    "https://www.google.com/search?q=site:trello.com+${COMPANY_NAME}" \
    "https://www.google.com/search?q=site:docs.google.com+${COMPANY_NAME}"; do
    log "  (manual check needed) $service_url"
  done
  {
    echo "## Manual Checks Needed"
    echo ""
    echo "- Search Google for third-party disclosures:"
    echo "  - site:trello.com $COMPANY_NAME"
    echo "  - site:docs.google.com $COMPANY_NAME"
    echo "  - site:prezi.com $COMPANY_NAME"
    echo ""
  } >> "$FINDINGS"

  # ── Broken URL check on *.uber.com (fixed $100 reward) ───────────────────
  log "Checking for broken external links..."
  if [[ -s "$ALL_URLS" ]]; then
    grep -E "^https?://" "$ALL_URLS" | grep -E "\.(pdf|zip|doc|docx)" | head -20 | while read -r url; do
      base_domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||')
      scope_ok "$base_domain" || continue
      status=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
      if [[ "$status" == "404" ]]; then
        warn "Broken URL: $url [$status]"
        echo "- broken_url: $url" >> "$FINDINGS"
      fi
    done
  fi

  ok "Quick wins scan complete. See: $FINDINGS"
  echo "## Quick wins" >> "$SUMMARY"
  echo "- takeover_candidates: $TAKEOVER_HITS" >> "$SUMMARY"
  echo "- findings_file: $FINDINGS" >> "$SUMMARY"
  echo "" >> "$SUMMARY"
fi

# ════════════════════════════════════════════════════════════════════════════
# Finalize
# ════════════════════════════════════════════════════════════════════════════
{
  echo "## Files"
  echo ""
  echo "- live_hosts: $LIVE_HOSTS"
  echo "- all_urls: $ALL_URLS"
  echo "- js_files: $JS_FILES"
  echo "- params: $PARAMS"
  echo "- quick_wins: $FINDINGS"
  echo ""
  echo "## What worked / Reusable technique"
  echo ""
  echo "- Subdomain enumeration via subfinder + crt.sh on $PROGRAM_ID"
  echo "- Live host probing filtered by scope gate before any active connection"
  echo ""
} >> "$SUMMARY"

ok "Recon complete. Summary: $SUMMARY"

# Ingest into learn_engine
if [[ -f "$LEARN_ENGINE" ]]; then
  python3 "$LEARN_ENGINE" --root "$CTF_ROOT" ingest \
    --session-id "$SESSION_ID" --source-path "$SUMMARY" 2>&1 | tail -2
fi
