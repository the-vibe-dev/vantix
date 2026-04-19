#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TARGET="${1:?usage: koth-claim-watch.sh <target_ip> [name] [interval_sec] [logfile] [statusfile]}"
NAME="${2:-${OPERATOR_NAME:-operator}}"
INTERVAL="${3:-2}"
LOGFILE="${4:-$ROOT_DIR/challenges/tryhackme/koth/claim_watch_${TARGET}.log}"
STATUSFILE="${5:-$ROOT_DIR/challenges/tryhackme/koth/koth_status_${TARGET}.json}"

claims=0
losses=0
unknown=0
last=""

mkdir -p "$(dirname "$LOGFILE")"
mkdir -p "$(dirname "$STATUSFILE")"

write_status() {
  local ts="$1"
  local state="$2"
  local cur="$3"
  python3 - "$STATUSFILE" "$LOGFILE" "$TARGET" "$NAME" "$ts" "$state" "$cur" "$claims" "$losses" "$unknown" <<'PY'
import json, os, sys

statusfile, logfile, target, desired_holder, ts, state, observed_holder, claims, losses, unknown = sys.argv[1:]
needs_retake = state in {"LOSS", "OTHER"}
data = {
    "target": target,
    "desired_holder": desired_holder,
    "ts": ts,
    "state": state,
    "observed_holder": observed_holder,
    "claims": int(claims),
    "losses": int(losses),
    "unknown": int(unknown),
    "needs_retake": needs_retake,
    "recovery_mode": False,
    "recovery_attempt_active": False,
    "source": "claim-watch",
    "logfile": logfile,
}
tmp = statusfile + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.replace(tmp, statusfile)
PY
}

echo "# claim watch start target=$TARGET name=$NAME interval=${INTERVAL}s ts=$(date -Iseconds)" | tee -a "$LOGFILE"
while true; do
  ts="$(date '+%F %T')"
  cur="$(curl -sS --max-time 3 "http://${TARGET}:9999/" 2>/dev/null | tr -d '\r\n' || true)"
  if [[ -z "$cur" ]]; then
    ((unknown+=1)) || true
    state="UNKNOWN"
  elif [[ "$cur" == "$NAME" ]]; then
    state="HOLD"
    if [[ "$last" != "$NAME" ]]; then
      ((claims+=1)) || true
      state="CLAIM"
    fi
  else
    if [[ "$last" == "$NAME" ]]; then
      ((losses+=1)) || true
      state="LOSS"
    else
      state="OTHER"
    fi
  fi
  printf '%s state=%s king=%s claims=%d losses=%d unknown=%d\n' "$ts" "$state" "${cur:-ERR}" "$claims" "$losses" "$unknown" | tee -a "$LOGFILE"
  write_status "$ts" "$state" "${cur:-ERR}"
  last="$cur"
  sleep "$INTERVAL"
done
