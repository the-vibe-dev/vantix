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
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1
paths=("$ROOT_DIR/memory" "$RUNTIME_ROOT" "$ARTIFACTS_ROOT")

for path in "${paths[@]}"; do
  [[ -e "$path" ]] || continue
  echo "checking $path"
  find "$path" \( -user root -o ! -writable \) -print 2>/dev/null | head -100 || true
  if [[ "$APPLY" -eq 1 ]]; then
    sudo chown -R "$(id -u):$(id -g)" "$path"
    find "$path" -type d -exec chmod u+rwx {} +
    find "$path" -type f -exec chmod u+rw {} +
  fi
done
if [[ "$APPLY" -ne 1 ]]; then
  echo "dry run only. Use --apply to repair project runtime paths."
fi
