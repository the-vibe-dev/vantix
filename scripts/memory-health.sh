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
STALE_MINUTES="${CTF_MEMORY_STALE_MINUTES:-30}"
python3 "$ROOT_DIR/scripts/memory-write.py" --root "$ROOT_DIR" --health --stale-minutes "$STALE_MINUTES"

bad=0
for path in "$ROOT_DIR/memory" "$RUNTIME_ROOT" "$ARTIFACTS_ROOT"; do
  [[ -e "$path" ]] || continue
  while IFS= read -r item; do
    [[ -z "$item" ]] && continue
    echo "root-owned-or-not-writable: $item" >&2
    bad=1
  done < <(find "$path" \( -user root -o ! -writable \) -print 2>/dev/null | head -100)
done
exit "$bad"
