#!/usr/bin/env bash
# bugbounty-hunter.sh — Bug bounty main orchestrator
#
# Ties together scope enforcement, recon, probing, and report generation
# into a single autonomous hunting session.
#
# Usage:
#   bugbounty-hunter.sh --program uber
#   bugbounty-hunter.sh --program uber --phase recon
#   bugbounty-hunter.sh --program uber --phase probe --vuln ssrf
#   bugbounty-hunter.sh --program uber --target api.uber.com --vuln xss
#   bugbounty-hunter.sh --program uber --session SESSION_ID --phase report
#   bugbounty-hunter.sh --program uber --install --dry-run
#
# Phases: recon | probe | report | all (default)
# Flags:
#   --install    run bugbounty-install.sh --check before starting
#   --dry-run    scope checks only, no active outbound probing
#   --strict     treat scope AMBIGUOUS as OUT_OF_SCOPE (no prompts)
#   --accounts FILE  two-account credentials file for IDOR testing

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SCRIPTS="$CTF_ROOT/scripts"
BB_DIR="$CTF_ROOT/agent_ops/bugbounty"
BB_PROGRAMS="$BB_DIR/programs"
ARTIFACTS_ROOT="$CTF_ROOT/artifacts"

PROGRAM_ID=""
PHASE="all"
SESSION_ID=""
TARGET_OVERRIDE=""
VULN_FILTER=""
ACCOUNTS_FILE=""
DO_INSTALL=false
DRY_RUN=false
STRICT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --program|-p)   PROGRAM_ID="$2";       shift 2 ;;
    --phase)        PHASE="$2";            shift 2 ;;
    --session)      SESSION_ID="$2";       shift 2 ;;
    --target|-t)    TARGET_OVERRIDE="$2";  shift 2 ;;
    --vuln)         VULN_FILTER="$2";      shift 2 ;;
    --accounts)     ACCOUNTS_FILE="$2";    shift 2 ;;
    --install)      DO_INSTALL=true;       shift ;;
    --dry-run)      DRY_RUN=true;          shift ;;
    --strict)       STRICT=true;           shift ;;
    -h|--help) grep '^#' "$0" | head -20 | sed 's/^# \?//'; exit 0 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

[[ -z "$PROGRAM_ID" ]] && { echo "[!] --program required"; exit 1; }

PROGRAM_YAML="$BB_PROGRAMS/$PROGRAM_ID/program.yaml"
[[ ! -f "$PROGRAM_YAML" ]] && { echo "[!] Program spec not found: $PROGRAM_YAML"; exit 1; }

# ── Logging ───────────────────────────────────────────────────────────────────
SESSION_ID="${SESSION_ID:-bb_$(date +%Y%m%d_%H%M%S)}"
SESSION_DIR="$ARTIFACTS_ROOT/bugbounty/$PROGRAM_ID/$SESSION_ID"
LOG_FILE="$SESSION_DIR/hunter.log"

mkdir -p "$SESSION_DIR"/{recon,fingerprint,findings,reports,quickwins}

ts()   { date +%H:%M:%S; }
log()  { echo "[$(ts)] $*" | tee -a "$LOG_FILE"; }
ok()   { echo "[$(ts)] [+] $*" | tee -a "$LOG_FILE"; }
warn() { echo "[$(ts)] [!] $*" | tee -a "$LOG_FILE"; }
fail() { echo "[$(ts)] [FAIL] $*" | tee -a "$LOG_FILE"; }
hr()   { echo "──────────────────────────────────────────" | tee -a "$LOG_FILE"; }

log "Session: $SESSION_ID"
log "Program: $PROGRAM_ID"
log "Phase:   $PHASE"
log "Dry-run: $DRY_RUN"
[[ -n "$TARGET_OVERRIDE" ]] && log "Target override: $TARGET_OVERRIDE"
[[ -n "$VULN_FILTER"     ]] && log "Vuln filter: $VULN_FILTER"
hr

# ── Scope check helper ────────────────────────────────────────────────────────
scope_gate() {
  local target="$1"
  local strict_flag=""
  $STRICT && strict_flag="--strict"

  local result
  result=$("$SCRIPTS/bugbounty-scope.sh" \
    --target "$target" \
    --program "$PROGRAM_ID" \
    --quiet \
    $strict_flag 2>/dev/null || true)

  case "$result" in
    IN_SCOPE)
      return 0
      ;;
    OUT_OF_SCOPE)
      warn "OUT_OF_SCOPE: $target — skipping"
      return 1
      ;;
    AMBIGUOUS)
      if $STRICT; then
        warn "AMBIGUOUS (strict→OOS): $target — skipping"
        return 1
      fi
      echo ""
      warn "SCOPE AMBIGUOUS: $target"
      warn "Could not confirm this target is in scope for $PROGRAM_ID."
      warn "Scope questions log: $BB_PROGRAMS/$PROGRAM_ID/scope_questions.log"
      echo ""
      read -rp "    [?] Proceed with $target? [y/N] " ans
      case "${ans,,}" in
        y|yes) log "Operator approved ambiguous target: $target"; return 0 ;;
        *)     warn "Skipping ambiguous target: $target"; return 1 ;;
      esac
      ;;
  esac
  return 1
}

# ── Tool installation check ───────────────────────────────────────────────────
if $DO_INSTALL; then
  hr
  log "Running tool check..."
  "$SCRIPTS/bugbounty-install.sh" --check 2>&1 | tee -a "$LOG_FILE" || true
  echo ""
  read -rp "[?] Install any missing tools now? [y/N] " ans
  if [[ "${ans,,}" == "y" ]]; then
    log "Installing missing tools..."
    "$SCRIPTS/bugbounty-install.sh" 2>&1 | tee -a "$LOG_FILE" || true
  fi
  hr
fi

# ── Verify scope API reachable ────────────────────────────────────────────────
verify_scope_api() {
  local api_url
  api_url=$(grep "domains:" "$PROGRAM_YAML" | grep "http" | awk '{print $2}' | tr -d '"' | head -1 || true)
  if [[ -z "$api_url" ]]; then
    log "No asset recon API configured for $PROGRAM_ID — using YAML scope only"
    return 0
  fi

  log "Verifying scope API: $api_url"
  local status
  status=$(curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "$api_url?offset=0&limit=1" 2>/dev/null || echo "000")
  if [[ "$status" == "200" ]]; then
    ok "Scope API reachable (HTTP $status)"
  else
    warn "Scope API returned HTTP $status — falling back to YAML scope"
  fi
}

verify_scope_api

# ── Write session manifest ────────────────────────────────────────────────────
MANIFEST="$SESSION_DIR/session.yaml"
cat > "$MANIFEST" <<YAML
session_id: $SESSION_ID
program: $PROGRAM_ID
phase: $PHASE
dry_run: $DRY_RUN
strict: $STRICT
started: $(date -u +%Y-%m-%dT%H:%M:%SZ)
target_override: "${TARGET_OVERRIDE:-}"
vuln_filter: "${VULN_FILTER:-}"
accounts_file: "${ACCOUNTS_FILE:-}"
YAML
ok "Session manifest: $MANIFEST"
hr

# ─────────────────────────────────────────────────────────────────────────────
# PHASE: RECON
# ─────────────────────────────────────────────────────────────────────────────
run_recon() {
  log "Starting recon phase..."

  if $DRY_RUN; then
    log "[dry-run] Would run: bugbounty-recon.sh --program $PROGRAM_ID --session $SESSION_ID"
    log "[dry-run] Scope check for wildcard targets in program.yaml:"

    # Dry-run: just check wildcards (stop at next YAML key at same indent level)
    mapfile -t WILDCARDS < <(
      awk '/^  wildcard_in_scope:/{found=1; next}
           found && /^  [a-z]/{exit}
           found && /^    - /{gsub(/^    - /,""); gsub(/["\x27]/,""); print}' \
        "$PROGRAM_YAML" || true
    )
    for wc in "${WILDCARDS[@]}"; do
      # Strip *. prefix for scope check
      base="${wc#\*.}"
      result=$("$SCRIPTS/bugbounty-scope.sh" \
        --target "$base" --program "$PROGRAM_ID" --quiet 2>/dev/null || echo "UNKNOWN")
      log "  [dry-run] scope_check: $wc → $result"
    done
    return 0
  fi

  local recon_args=(
    --program "$PROGRAM_ID"
    --session "$SESSION_ID"
  )
  [[ -n "$TARGET_OVERRIDE" ]] && recon_args+=(--target-override "$TARGET_OVERRIDE")

  "$SCRIPTS/bugbounty-recon.sh" "${recon_args[@]}" 2>&1 | tee -a "$LOG_FILE" || {
    fail "Recon phase encountered errors (check log)"
  }

  ok "Recon phase complete"

  # Summarize what was found
  local live_count=0
  [[ -f "$SESSION_DIR/recon/live_hosts.txt" ]] && \
    live_count=$(wc -l < "$SESSION_DIR/recon/live_hosts.txt" || echo 0)
  log "Live hosts found: $live_count"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE: PROBE
# ─────────────────────────────────────────────────────────────────────────────
run_probe() {
  log "Starting probe phase..."

  if $DRY_RUN; then
    log "[dry-run] Would run: bugbounty-probe.sh --program $PROGRAM_ID --session $SESSION_ID"
    [[ -n "$VULN_FILTER"     ]] && log "[dry-run]   --vuln-type $VULN_FILTER"
    [[ -n "$TARGET_OVERRIDE" ]] && log "[dry-run]   --target $TARGET_OVERRIDE"

    # Scope-check the override target if provided
    if [[ -n "$TARGET_OVERRIDE" ]]; then
      if scope_gate "$TARGET_OVERRIDE"; then
        log "[dry-run] Target $TARGET_OVERRIDE is IN_SCOPE — would proceed"
      else
        log "[dry-run] Target $TARGET_OVERRIDE is NOT in scope — would skip"
      fi
    fi
    return 0
  fi

  # Confirm recon data exists (unless target override provided)
  if [[ -z "$TARGET_OVERRIDE" ]] && [[ ! -f "$SESSION_DIR/recon/live_hosts.txt" ]]; then
    warn "No recon data found for session $SESSION_ID"
    warn "Run with --phase recon first, or provide --target override"
    read -rp "[?] Continue anyway? [y/N] " ans
    [[ "${ans,,}" != "y" ]] && { log "Probe aborted by operator"; return 1; }
  fi

  local probe_args=(
    --program "$PROGRAM_ID"
    --session "$SESSION_ID"
  )
  [[ -n "$VULN_FILTER"     ]] && probe_args+=(--vuln-type "$VULN_FILTER")
  [[ -n "$TARGET_OVERRIDE" ]] && probe_args+=(--target "$TARGET_OVERRIDE")
  [[ -n "$ACCOUNTS_FILE"   ]] && probe_args+=(--accounts "$ACCOUNTS_FILE")

  "$SCRIPTS/bugbounty-probe.sh" "${probe_args[@]}" 2>&1 | tee -a "$LOG_FILE" || {
    fail "Probe phase encountered errors (check log)"
  }

  ok "Probe phase complete"

  # Count findings
  local finding_count=0
  finding_count=$(find "$SESSION_DIR/findings" -name "*.md" 2>/dev/null | wc -l || echo 0)
  log "Findings generated: $finding_count"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE: REPORT
# ─────────────────────────────────────────────────────────────────────────────
run_report() {
  log "Starting report phase..."

  local findings_dir="$SESSION_DIR/findings"
  mapfile -t finding_files < <(find "$findings_dir" -name "*.md" 2>/dev/null \
    | grep -v "_H1_REPORT" | sort || true)

  if [[ ${#finding_files[@]} -eq 0 ]]; then
    warn "No finding files found in $findings_dir"
    log "Probe phase must produce findings before reports can be generated."
    return 0
  fi

  log "Generating H1 reports for ${#finding_files[@]} finding(s)..."

  local report_args=(
    --program "$PROGRAM_ID"
    --session "$SESSION_ID"
  )
  [[ -n "$VULN_FILTER" ]] && report_args+=(--vuln "$VULN_FILTER")

  "$SCRIPTS/bugbounty-report.sh" "${report_args[@]}" 2>&1 | tee -a "$LOG_FILE" || {
    fail "Report phase encountered errors"
  }

  ok "Report phase complete"

  # List generated reports
  local report_count=0
  report_count=$(find "$findings_dir" -name "*_H1_REPORT.md" 2>/dev/null | wc -l || echo 0)
  log "H1 reports generated: $report_count"

  if [[ "$report_count" -gt 0 ]]; then
    log "Reports:"
    find "$findings_dir" -name "*_H1_REPORT.md" 2>/dev/null | while read -r r; do
      log "  → $r"
    done
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE: LEARN (ingest findings into learn_engine)
# ─────────────────────────────────────────────────────────────────────────────
run_learn() {
  local findings_dir="$SESSION_DIR/findings"
  mapfile -t finding_files < <(find "$findings_dir" -name "*.md" 2>/dev/null \
    | grep -v "_H1_REPORT" | sort || true)

  if [[ ${#finding_files[@]} -eq 0 ]]; then
    log "No findings to ingest into learn_engine."
    return 0
  fi

  log "Ingesting ${#finding_files[@]} finding(s) into learn_engine..."

  LEARN_DIR="$CTF_ROOT/memory/bugbounty/$PROGRAM_ID/$SESSION_ID"
  mkdir -p "$LEARN_DIR"

  for f in "${finding_files[@]}"; do
    cp "$f" "$LEARN_DIR/" 2>/dev/null || true
  done

  if command -v python3 &>/dev/null && [[ -f "$SCRIPTS/learn_engine.py" ]]; then
    python3 "$SCRIPTS/learn_engine.py" \
      --root "$CTF_ROOT" \
      startup-digest 2>&1 | tail -5 | tee -a "$LOG_FILE" || true
    ok "learn_engine ingestion complete"
  else
    warn "learn_engine.py not found or python3 unavailable — skipping auto-ingest"
    log "Findings copied to: $LEARN_DIR (ingest manually)"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN — Execute selected phases
# ─────────────────────────────────────────────────────────────────────────────
hr
case "$PHASE" in
  recon)
    run_recon
    ;;
  probe)
    run_probe
    ;;
  report)
    run_report
    ;;
  learn)
    run_learn
    ;;
  all)
    run_recon
    hr
    run_probe
    hr
    run_report
    hr
    run_learn
    ;;
  *)
    echo "[!] Unknown phase: $PHASE (valid: recon, probe, report, learn, all)"
    exit 1
    ;;
esac

hr
ok "Session $SESSION_ID complete."
log "Artifacts: $SESSION_DIR"

# ── Session summary ───────────────────────────────────────────────────────────
LIVE=$([ -f "$SESSION_DIR/recon/live_hosts.txt" ] && wc -l < "$SESSION_DIR/recon/live_hosts.txt" || echo 0)
FINDINGS=$(find "$SESSION_DIR/findings" -name "*.md" 2>/dev/null | grep -v H1_REPORT | wc -l || echo 0)
REPORTS=$(find "$SESSION_DIR/findings" -name "*H1_REPORT.md" 2>/dev/null | wc -l || echo 0)

echo ""
echo "┌─────────────────────────────────────────────┐"
echo "│  SESSION SUMMARY: $SESSION_ID"
echo "│  Program:  $PROGRAM_ID"
printf "│  Live hosts found:  %s\n" "$LIVE"
printf "│  Findings written:  %s\n" "$FINDINGS"
printf "│  H1 reports ready:  %s\n" "$REPORTS"
echo "│  Log: $LOG_FILE"
echo "└─────────────────────────────────────────────┘"
echo ""

if [[ "$REPORTS" -gt 0 ]]; then
  echo "[!] NEXT STEPS:"
  echo "    1. Review each H1 report and fill in the [Summary] and [Steps to Reproduce] placeholders"
  echo "    2. Attach screenshots / video PoC if available"
  echo "    3. Verify target is in scope at: https://appsec-analysis.uber.com/public/bugbounty/ListDomains"
  echo "    4. Check for duplicates on HackerOne before submitting"
  echo "    5. Submit at: https://hackerone.com/uber"
  echo ""
fi
