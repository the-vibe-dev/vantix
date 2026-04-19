#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
default_runtime_root() {
  local state_home="${XDG_STATE_HOME:-$HOME/.local/state}"
  local repo_id
  repo_id="$(printf '%s' "$ROOT_DIR" | sha1sum | awk '{print substr($1,1,8)}')"
  printf '%s/ctf-security-ops/%s-%s\n' "$state_home" "$(basename "$ROOT_DIR")" "$repo_id"
}
RUNTIME_ROOT="${SECOPS_RUNTIME_ROOT:-$(default_runtime_root)}"
ARTIFACTS_ROOT="${SECOPS_ARTIFACTS_ROOT:-$ROOT_DIR/artifacts}"
SESSION_ID="${SESSION_ID:-}"
AGENT_ID="${AGENT_ID:-${CODEX_AGENT_ID:-$(hostname):$$}}"
INTERVAL_SECONDS="${CTF_MEMORY_HEARTBEAT_SECONDS:-600}"
OBJECTIVE="${OBJECTIVE:-memory watcher heartbeat}"
LAST_SIG=""

snapshot_sig() {
  find "$ROOT_DIR/memory" "$ARTIFACTS_ROOT" "$RUNTIME_ROOT" -type f -printf '%T@ %p\n' 2>/dev/null | sort | tail -50 | sha256sum | awk '{print $1}'
}

write_mem() {
  local mode="$1" phase="$2" done="$3" next="$4"
  "$ROOT_DIR/scripts/memory-write.py" --root "$ROOT_DIR" --mode "$mode" --session-id "$SESSION_ID" --agent "$AGENT_ID" --phase "$phase" --objective "$OBJECTIVE" --done "$done" --next "$next" --context "watcher" >/dev/null 2>&1 || true
}

shutdown() {
  write_mem handoff watcher-exit "memory watcher stopped" "resume from latest dense memory record"
}
trap shutdown EXIT INT TERM

write_mem heartbeat watcher-start "memory watcher started" "continue active session"
while true; do
  sleep "$INTERVAL_SECONDS"
  sig="$(snapshot_sig || true)"
  if [[ -z "$LAST_SIG" || "$sig" != "$LAST_SIG" ]]; then
    write_mem heartbeat watcher "activity observed" "continue active session"
    LAST_SIG="$sig"
  fi
done
