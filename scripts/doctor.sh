#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "$ROOT_DIR/scripts/lib/load-env.sh"
load_repo_env "$ROOT_DIR"
default_runtime_root() {
  local state_home="${XDG_STATE_HOME:-$HOME/.local/state}"
  local repo_id
  repo_id="$(printf '%s' "$ROOT_DIR" | sha1sum | awk '{print substr($1,1,8)}')"
  printf '%s/ctf-security-ops/%s-%s\n' "$state_home" "$(basename "$ROOT_DIR")" "$repo_id"
}
RUNTIME_ROOT="${SECOPS_RUNTIME_ROOT:-$(default_runtime_root)}"
ARTIFACTS_ROOT="${SECOPS_ARTIFACTS_ROOT:-$ROOT_DIR/artifacts}"
status=0

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  echo "[INFO] os=${PRETTY_NAME:-${NAME:-unknown}}"
fi
echo "[INFO] codex_bin=${SECOPS_CODEX_BIN:-codex}"
command -v "${SECOPS_CODEX_BIN:-codex}" >/dev/null 2>&1 && echo "[OK] codex available" || echo "[WARN] codex unavailable"
command -v node >/dev/null 2>&1 && echo "[OK] node available" || echo "[WARN] node unavailable"
command -v corepack >/dev/null 2>&1 && echo "[OK] corepack available" || echo "[WARN] corepack unavailable"
command -v pnpm >/dev/null 2>&1 && echo "[OK] pnpm available" || echo "[WARN] pnpm unavailable"
[[ -x "$ROOT_DIR/tools/cve-search/local_status.sh" ]] && echo "[OK] cve-search local scripts present" || echo "[WARN] cve-search local scripts missing"

check_dir() {
  local path="$1"
  mkdir -p "$path" 2>/dev/null || true
  if [[ ! -w "$path" ]]; then
    echo "[FAIL] not writable: $path" >&2
    status=1
  else
    echo "[OK] writable: $path"
  fi
}

check_dir "$ROOT_DIR/memory"
check_dir "$RUNTIME_ROOT"
check_dir "$ARTIFACTS_ROOT"

root_owned=$(find "$ROOT_DIR/memory" "$RUNTIME_ROOT" "$ARTIFACTS_ROOT" -user root -print 2>/dev/null | head -20 || true)
if [[ -n "$root_owned" ]]; then
  echo "[FAIL] root-owned runtime files detected:" >&2
  echo "$root_owned" >&2
  echo "Run: bash scripts/fix-permissions.sh --apply" >&2
  status=1
fi
exit "$status"
