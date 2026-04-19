#!/usr/bin/env bash
# koth-opponent-watch.sh — Continuous opponent activity monitor for KoTH rounds
#
# Polls a target via SSH every N seconds, detects new files, processes,
# connections, auth events, crontab/service changes, and king transitions.
# Optionally auto-captures opponent tools for analysis.
#
# Usage:
#   koth-opponent-watch.sh <target_ip> [options]
#
# Options:
#   --ssh-key KEY        SSH private key for target access
#   --ssh-user USER      SSH user (default: root)
#   --interval N         Poll interval in seconds (default: 10)
#   --logfile PATH       Log output path (default: auto-generated)
#   --auto-capture       Auto-pull new files and run tool-extractor
#   --session ID         Session ID for artifact storage
#   --our-ip IP          Our VPN IP to exclude from opponent tracking

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TOOL_EXTRACTOR="$CTF_ROOT/scripts/tool-extractor.sh"
OPP_TOOLS_DIR="$CTF_ROOT/memory/opponent_tools"

TARGET="${1:?usage: koth-opponent-watch.sh <target_ip> [--ssh-key KEY] [--ssh-user USER] [--interval N] [--auto-capture]}"
shift || true

SSH_KEY=""
SSH_USER="root"
INTERVAL=10
LOGFILE=""
AUTO_CAPTURE=false
SESSION_ID=""
OUR_IP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-key)      SSH_KEY="$2"; shift 2 ;;
    --ssh-user)     SSH_USER="$2"; shift 2 ;;
    --interval)     INTERVAL="$2"; shift 2 ;;
    --logfile)      LOGFILE="$2"; shift 2 ;;
    --auto-capture) AUTO_CAPTURE=true; shift ;;
    --session)      SESSION_ID="$2"; shift 2 ;;
    --our-ip)       OUR_IP="$2"; shift 2 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

[[ -z "$SESSION_ID" ]] && SESSION_ID="oppwatch-$(date +%Y%m%d-%H%M%S)"
[[ -z "$LOGFILE" ]] && LOGFILE="$CTF_ROOT/challenges/tryhackme/koth/opponent_watch_${TARGET}.log"
mkdir -p "$(dirname "$LOGFILE")"

BASELINE_DIR="/tmp/koth_oppwatch_$$"
mkdir -p "$BASELINE_DIR"
cleanup() { rm -rf "$BASELINE_DIR"; }
trap cleanup EXIT

# ── SSH helpers (reused from tool-extractor pattern) ─────────────────────────

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR)

ssh_run() {
  if [[ -n "$SSH_KEY" ]]; then
    ssh "${SSH_OPTS[@]}" -i "$SSH_KEY" "${SSH_USER}@${TARGET}" "$1" 2>/dev/null
  else
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${TARGET}" "$1" 2>/dev/null
  fi
}

ssh_pull() {
  local src="$1" dst="$2"
  if [[ -n "$SSH_KEY" ]]; then
    scp "${SSH_OPTS[@]}" -i "$SSH_KEY" "${SSH_USER}@${TARGET}:${src}" "$dst" 2>/dev/null
  else
    scp "${SSH_OPTS[@]}" "${SSH_USER}@${TARGET}:${src}" "$dst" 2>/dev/null
  fi
}

# ── Logging ──────────────────────────────────────────────────────────────────

log_event() {
  local type="$1"; shift
  printf '%s type=%s %s\n' "$(date -u +%FT%TZ)" "$type" "$*" | tee -a "$LOGFILE"
}

# ── Baseline capture ─────────────────────────────────────────────────────────

echo "[*] koth-opponent-watch: target=$TARGET interval=${INTERVAL}s session=$SESSION_ID"
echo "[*] Log: $LOGFILE"
echo "[*] Auto-capture: $AUTO_CAPTURE"

log_event "watch_start" "target=$TARGET user=$SSH_USER interval=${INTERVAL}s auto_capture=$AUTO_CAPTURE"

echo "[*] Taking baseline snapshot..."

# Detect our own IP if not provided
if [[ -z "$OUR_IP" ]]; then
  OUR_IP=$(ssh_run "who am i 2>/dev/null | grep -oP '\(\K[0-9.]+'" || true)
  [[ -n "$OUR_IP" ]] && echo "[*] Detected our IP: $OUR_IP"
fi

# File baseline: mark timestamp on target
ssh_run "touch /tmp/.koth_oppwatch_mark" || true

# Process baseline
ssh_run "ps aux --no-headers 2>/dev/null | awk '{print \$2,\$1,\$11}' | sort" > "$BASELINE_DIR/procs.txt" 2>/dev/null || true

# Connection baseline
ssh_run "ss -tunp --no-header 2>/dev/null" > "$BASELINE_DIR/conns.txt" 2>/dev/null || true

# Crontab baseline
ssh_run "crontab -l 2>/dev/null; cat /etc/cron.d/* 2>/dev/null; cat /var/spool/cron/crontabs/* 2>/dev/null" > "$BASELINE_DIR/cron.txt" 2>/dev/null || true

# Service baseline
ssh_run "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print \$1}' | sort" > "$BASELINE_DIR/services.txt" 2>/dev/null || true

# Auth log position
ssh_run "wc -l /var/log/auth.log 2>/dev/null | awk '{print \$1}'" > "$BASELINE_DIR/auth_lines.txt" 2>/dev/null || true

# King baseline
LAST_KING=$(curl -sS --max-time 3 "http://${TARGET}:9999/" 2>/dev/null | tr -d '\r\n' || true)

log_event "baseline_complete" "procs=$(wc -l < "$BASELINE_DIR/procs.txt") conns=$(wc -l < "$BASELINE_DIR/conns.txt") services=$(wc -l < "$BASELINE_DIR/services.txt") king=${LAST_KING:-unknown}"

# Track captured files to avoid re-capture
declare -A CAPTURED_FILES=()

# ── Main watch loop ──────────────────────────────────────────────────────────

capture_file() {
  local remote_path="$1"
  local fname
  fname=$(basename "$remote_path")

  # Skip if already captured
  [[ -n "${CAPTURED_FILES[$remote_path]:-}" ]] && return

  local ts
  ts=$(date +%Y%m%d-%H%M%S)
  local cap_dir="$OPP_TOOLS_DIR/$SESSION_ID/$ts"
  mkdir -p "$cap_dir"

  if ssh_pull "$remote_path" "$cap_dir/$fname" 2>/dev/null; then
    CAPTURED_FILES["$remote_path"]=1
    log_event "captured" "file=$remote_path -> $cap_dir/$fname"

    # Run tool-extractor if available
    if [[ -x "$TOOL_EXTRACTOR" ]]; then
      "$TOOL_EXTRACTOR" -d "$cap_dir" --session "$SESSION_ID" >/dev/null 2>&1 &
    fi
  fi
}

cycle=0
while true; do
  cycle=$((cycle + 1))

  # ── King check ──
  cur_king=$(curl -sS --max-time 3 "http://${TARGET}:9999/" 2>/dev/null | tr -d '\r\n' || true)
  if [[ -n "$cur_king" && "$cur_king" != "$LAST_KING" ]]; then
    log_event "king_change" "from=${LAST_KING:-unknown} to=$cur_king"
    LAST_KING="$cur_king"
  fi

  # ── New files ──
  NEW_FILES=$(ssh_run "find /tmp /dev/shm /var/tmp /run \
    -newer /tmp/.koth_oppwatch_mark -type f \
    -not -name '.koth_oppwatch_mark' -not -name '.kh_*' \
    -not -path '*/koth_oppwatch_*' \
    -printf '%s %u %p\n' 2>/dev/null | head -30" || true)

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    fsize=$(echo "$line" | awk '{print $1}')
    fowner=$(echo "$line" | awk '{print $2}')
    fpath=$(echo "$line" | awk '{print $3}')
    [[ -z "$fpath" ]] && continue

    # Skip our own files
    [[ "$fpath" == *"koth_oppwatch"* || "$fpath" == *"reclaim"* || "$fpath" == *".kh_"* ]] && continue

    log_event "new_file" "path=$fpath size=$fsize owner=$fowner"

    if $AUTO_CAPTURE; then
      capture_file "$fpath"
    fi
  done <<< "$NEW_FILES"

  # Update mark for next cycle
  ssh_run "touch /tmp/.koth_oppwatch_mark" 2>/dev/null || true

  # ── New processes (every 3rd cycle to reduce SSH load) ──
  if (( cycle % 3 == 0 )); then
    CURRENT_PROCS=$(ssh_run "ps aux --no-headers 2>/dev/null | awk '{print \$2,\$1,\$11}' | sort" || true)
    NEW_PROCS=$(comm -13 "$BASELINE_DIR/procs.txt" <(echo "$CURRENT_PROCS") 2>/dev/null || true)

    while IFS= read -r pline; do
      [[ -z "$pline" ]] && continue
      pid=$(echo "$pline" | awk '{print $1}')
      puser=$(echo "$pline" | awk '{print $2}')
      pcmd=$(echo "$pline" | awk '{print $3}')
      # Skip kernel threads and our own processes
      [[ "$pcmd" == "["* ]] && continue
      log_event "new_proc" "pid=$pid user=$puser cmd=$pcmd"
    done <<< "$NEW_PROCS"

    # Update baseline
    echo "$CURRENT_PROCS" > "$BASELINE_DIR/procs.txt"
  fi

  # ── New connections (every 3rd cycle) ──
  if (( cycle % 3 == 1 )); then
    CURRENT_CONNS=$(ssh_run "ss -tunp --no-header 2>/dev/null" || true)
    NEW_CONNS=$(comm -13 <(sort "$BASELINE_DIR/conns.txt") <(echo "$CURRENT_CONNS" | sort) 2>/dev/null || true)

    while IFS= read -r cline; do
      [[ -z "$cline" ]] && continue
      proto=$(echo "$cline" | awk '{print $1}')
      local_addr=$(echo "$cline" | awk '{print $4}')
      remote_addr=$(echo "$cline" | awk '{print $5}')
      # Skip connections from our IP
      [[ -n "$OUR_IP" && "$remote_addr" == *"$OUR_IP"* ]] && continue
      log_event "new_conn" "proto=$proto local=$local_addr remote=$remote_addr"
    done <<< "$NEW_CONNS"

    echo "$CURRENT_CONNS" > "$BASELINE_DIR/conns.txt"
  fi

  # ── Auth log (every 3rd cycle) ──
  if (( cycle % 3 == 2 )); then
    PREV_LINES=$(cat "$BASELINE_DIR/auth_lines.txt" 2>/dev/null || echo "0")
    AUTH_NEW=$(ssh_run "tail -n +$((PREV_LINES + 1)) /var/log/auth.log 2>/dev/null | grep -i 'accepted\|session opened' | head -20" || true)

    while IFS= read -r aline; do
      [[ -z "$aline" ]] && continue
      # Skip our own IP
      [[ -n "$OUR_IP" && "$aline" == *"$OUR_IP"* ]] && continue
      log_event "ssh_login" "event=$aline"
    done <<< "$AUTH_NEW"

    ssh_run "wc -l /var/log/auth.log 2>/dev/null | awk '{print \$1}'" > "$BASELINE_DIR/auth_lines.txt" 2>/dev/null || true
  fi

  # ── Crontab changes (every 6th cycle) ──
  if (( cycle % 6 == 0 )); then
    CURRENT_CRON=$(ssh_run "crontab -l 2>/dev/null; cat /etc/cron.d/* 2>/dev/null; cat /var/spool/cron/crontabs/* 2>/dev/null" || true)
    NEW_CRON=$(comm -13 <(sort "$BASELINE_DIR/cron.txt") <(echo "$CURRENT_CRON" | sort) 2>/dev/null || true)

    while IFS= read -r crline; do
      [[ -z "$crline" ]] && continue
      [[ "$crline" == "#"* ]] && continue
      log_event "new_cron" "entry=$crline"
    done <<< "$NEW_CRON"

    echo "$CURRENT_CRON" > "$BASELINE_DIR/cron.txt"
  fi

  # ── Service changes (every 6th cycle) ──
  if (( cycle % 6 == 3 )); then
    CURRENT_SVCS=$(ssh_run "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print \$1}' | sort" || true)
    NEW_SVCS=$(comm -13 "$BASELINE_DIR/services.txt" <(echo "$CURRENT_SVCS") 2>/dev/null || true)

    while IFS= read -r sline; do
      [[ -z "$sline" ]] && continue
      log_event "new_service" "name=$sline"
    done <<< "$NEW_SVCS"

    echo "$CURRENT_SVCS" > "$BASELINE_DIR/services.txt"
  fi

  sleep "$INTERVAL"
done
