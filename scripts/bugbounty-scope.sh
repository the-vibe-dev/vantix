#!/usr/bin/env bash
# bugbounty-scope.sh — Bug bounty scope enforcement gate
#
# MUST be called before every active outbound request to a target.
# Exits 0 (IN_SCOPE), exits 1 (OUT_OF_SCOPE), exits 2 (AMBIGUOUS).
# Logs every check. AMBIGUOUS is treated as a pause-and-ask situation.
#
# Usage:
#   bugbounty-scope.sh --target TARGET --program PROGRAM_ID
#   bugbounty-scope.sh --target api.uber.com --program uber
#   bugbounty-scope.sh --target 10.10.10.5 --program uber --ip
#   bugbounty-scope.sh --target evil.com --program uber --strict   # AMBIGUOUS → OOS
#
# Exit codes:
#   0 = IN_SCOPE
#   1 = OUT_OF_SCOPE
#   2 = AMBIGUOUS (ask operator before proceeding)

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BB_PROGRAMS="$CTF_ROOT/agent_ops/bugbounty/programs"

TARGET=""
PROGRAM_ID=""
IS_IP=false
STRICT=false
QUIET=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target|-t)   TARGET="$2";     shift 2 ;;
    --program|-p)  PROGRAM_ID="$2"; shift 2 ;;
    --ip)          IS_IP=true;      shift ;;
    --strict)      STRICT=true;     shift ;;   # treat AMBIGUOUS as OUT_OF_SCOPE
    --quiet|-q)    QUIET=true;      shift ;;
    --dry-run)     DRY_RUN=true;    shift ;;
    -h|--help) grep '^#' "$0" | head -15 | sed 's/^# \?//'; exit 0 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

[[ -z "$TARGET" ]]     && { echo "[!] --target required"; exit 1; }
[[ -z "$PROGRAM_ID" ]] && { echo "[!] --program required"; exit 1; }

PROGRAM_DIR="$BB_PROGRAMS/$PROGRAM_ID"
PROGRAM_YAML="$PROGRAM_DIR/program.yaml"
[[ ! -f "$PROGRAM_YAML" ]] && { echo "[!] Program spec not found: $PROGRAM_YAML"; exit 1; }

SCOPE_LOG="$PROGRAM_DIR/scope_checks.log"
SCOPE_QUESTIONS="$PROGRAM_DIR/scope_questions.log"
SCOPE_CACHE="/tmp/bb_scope_cache_${PROGRAM_ID}.json"
CACHE_TTL_MIN=60

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "[$(ts)] $*" >> "$SCOPE_LOG"; $QUIET || echo "$*"; }

# ── YAML helpers (pure bash, no yq needed) ────────────────────────────────────
yaml_list() {
  local key="$1"
  grep -A100 "^  ${key}:" "$PROGRAM_YAML" 2>/dev/null | \
    tail -n +2 | grep '^    - ' | sed 's/^    - //' | sed 's/"//g' | sed "s/'//g" | \
    grep -v '^[[:space:]]*$' || true
}

yaml_val() {
  local key="$1"
  grep "^  ${key}:" "$PROGRAM_YAML" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo ""
}

# ── Extract scope data from YAML ──────────────────────────────────────────────
mapfile -t WILDCARDS < <(yaml_list "wildcard_in_scope")
mapfile -t OOS_DOMAINS < <(yaml_list "explicit_out_of_scope_domains")
mapfile -t EXPLICIT_IN_SCOPE < <(yaml_list "explicit_in_scope")

RECON_DOMAINS_API=$(grep "domains:" "$PROGRAM_YAML" | grep "appsec-analysis\|ListDomains" | awk '{print $2}' | tr -d '"' | head -1 || true)
RECON_IPS_API=$(grep "ips:" "$PROGRAM_YAML" | grep "appsec-analysis\|ListIPs" | awk '{print $2}' | tr -d '"' | head -1 || true)
CACHE_TTL_MIN=$(grep "cache_ttl_minutes:" "$PROGRAM_YAML" | awk '{print $2}' | head -1 || echo 60)

# ── Normalize target ──────────────────────────────────────────────────────────
# Strip scheme and path: https://api.uber.com/v1/thing → api.uber.com
TARGET_CLEAN=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/.*||' | tr '[:upper:]' '[:lower:]')

# ── Fetch and cache scope API ─────────────────────────────────────────────────
fetch_scope_api() {
  local url="$1" kind="$2"
  if [[ -z "$url" ]]; then return 1; fi

  # Check cache freshness
  if [[ -f "$SCOPE_CACHE" ]]; then
    local cache_age
    cache_age=$(( ($(date +%s) - $(date -r "$SCOPE_CACHE" +%s 2>/dev/null || echo 0)) / 60 ))
    if [[ "$cache_age" -lt "$CACHE_TTL_MIN" ]]; then
      return 0  # cache still fresh
    fi
  fi

  log "[scope] Refreshing $kind list from $url..."
  local response
  response=$(curl -sk --max-time 15 "$url?offset=0&limit=5000" 2>/dev/null || true)
  if [[ -n "$response" ]]; then
    echo "$response" > "$SCOPE_CACHE"
    log "[scope] $kind list cached ($(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "?") entries)"
  fi
}

# Try to refresh scope from API (non-fatal if unavailable)
if [[ -n "$RECON_DOMAINS_API" ]]; then
  fetch_scope_api "$RECON_DOMAINS_API" "domains" 2>/dev/null || true
fi

# Pull domains from cache if available
LIVE_SCOPE_DOMAINS=()
if [[ -f "$SCOPE_CACHE" ]]; then
  mapfile -t LIVE_SCOPE_DOMAINS < <(
    python3 -c "
import sys, json
try:
    data = json.load(open('$SCOPE_CACHE'))
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                print(item.lower())
            elif isinstance(item, dict):
                for key in ('domain','hostname','asset','identifier'):
                    if key in item:
                        print(str(item[key]).lower())
                        break
except: pass
" 2>/dev/null || true)
fi

# ── Decision logic ────────────────────────────────────────────────────────────
RESULT="AMBIGUOUS"
REASON=""

# 1. Check explicit OOS domains first (fast reject)
for oos in "${OOS_DOMAINS[@]}"; do
  oos_clean="${oos// /}"
  if [[ "$TARGET_CLEAN" == "$oos_clean" ]] || [[ "$TARGET_CLEAN" == *"$oos_clean"* ]]; then
    RESULT="OUT_OF_SCOPE"
    REASON="matches explicit OOS domain: $oos"
    break
  fi
done

# 2. Check explicit in-scope from YAML
if [[ "$RESULT" == "AMBIGUOUS" ]]; then
  for domain in "${EXPLICIT_IN_SCOPE[@]}"; do
    if [[ "$TARGET_CLEAN" == "$domain" ]] || [[ "$TARGET_CLEAN" == *".$domain" ]]; then
      RESULT="IN_SCOPE"
      REASON="matches explicit in-scope: $domain"
      break
    fi
  done
fi

# 3. Check live scope API results
if [[ "$RESULT" == "AMBIGUOUS" && ${#LIVE_SCOPE_DOMAINS[@]} -gt 0 ]]; then
  for domain in "${LIVE_SCOPE_DOMAINS[@]}"; do
    if [[ "$TARGET_CLEAN" == "$domain" ]] || [[ "$TARGET_CLEAN" == *".$domain" ]]; then
      RESULT="IN_SCOPE"
      REASON="matches live scope API: $domain"
      break
    fi
  done
fi

# 4. Check wildcard patterns (*.uber.com → anything.uber.com)
if [[ "$RESULT" == "AMBIGUOUS" ]]; then
  for wc in "${WILDCARDS[@]}"; do
    # Strip leading *. for comparison
    base="${wc#\*.}"
    base="${base#\*.}"
    if [[ "$TARGET_CLEAN" == "$base" ]] || [[ "$TARGET_CLEAN" == *".$base" ]]; then
      RESULT="IN_SCOPE"
      REASON="matches wildcard: $wc"
      break
    fi
  done
fi

# 5. Strict mode: AMBIGUOUS → OUT_OF_SCOPE
if [[ "$RESULT" == "AMBIGUOUS" ]] && $STRICT; then
  RESULT="OUT_OF_SCOPE"
  REASON="ambiguous target treated as out-of-scope (--strict mode)"
fi

# ── Log and output result ─────────────────────────────────────────────────────
log "[scope] target=$TARGET_CLEAN result=$RESULT reason=${REASON:-unmatched}"

if [[ "$RESULT" == "AMBIGUOUS" ]]; then
  {
    echo "$(ts) AMBIGUOUS target=$TARGET_CLEAN program=$PROGRAM_ID"
    echo "  No definitive scope match found."
    echo "  Check: $RECON_DOMAINS_API"
    echo "  Ask operator before proceeding."
  } >> "$SCOPE_QUESTIONS"
fi

# ── Output ────────────────────────────────────────────────────────────────────
echo "$RESULT"

case "$RESULT" in
  IN_SCOPE)
    log "[scope] ✓ $TARGET_CLEAN → IN_SCOPE ($REASON)"
    exit 0
    ;;
  OUT_OF_SCOPE)
    log "[scope] ✗ $TARGET_CLEAN → OUT_OF_SCOPE ($REASON)"
    exit 1
    ;;
  AMBIGUOUS)
    log "[scope] ? $TARGET_CLEAN → AMBIGUOUS — logged to $SCOPE_QUESTIONS"
    echo "[!] Scope unclear for: $TARGET_CLEAN"
    echo "    Check $RECON_DOMAINS_API to verify."
    echo "    Logged to: $SCOPE_QUESTIONS"
    exit 2
    ;;
esac
