#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "$ROOT_DIR/scripts/lib/load-env.sh"
load_repo_env "$ROOT_DIR"

ensure_pkg() {
  local cmd="$1"
  shift
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  echo "[*] Installing bootstrap packages: $*"
  sudo apt-get update
  sudo apt-get install -y "$@"
}

ensure_pkg python3 python3
python3 -m venv --help >/dev/null 2>&1 || ensure_pkg python3-venv python3-venv
python3 -m pip --help >/dev/null 2>&1 || ensure_pkg pip3 python3-pip
command -v git >/dev/null 2>&1 || ensure_pkg git git

if [[ ! -x "$ROOT_DIR/.venv/bin/python" ]]; then
  python3 -m venv "$ROOT_DIR/.venv"
fi

"$ROOT_DIR/.venv/bin/python" -m pip install --upgrade pip >/dev/null
"$ROOT_DIR/.venv/bin/python" -m pip install -e "$ROOT_DIR[dev]" >/dev/null

exec "$ROOT_DIR/.venv/bin/python" -m secops.updater --repo-root "$ROOT_DIR" "$@"
