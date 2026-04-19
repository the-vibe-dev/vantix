#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "$ROOT_DIR/scripts/lib/load-env.sh"
load_repo_env "$ROOT_DIR"
cd "$ROOT_DIR"

HOST="${SECOPS_HOST:-127.0.0.1}"
PORT="${SECOPS_PORT:-8787}"
VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"

if [[ -x "$VENV_PYTHON" ]]; then
  exec "$VENV_PYTHON" -m uvicorn secops.app:app --host "$HOST" --port "$PORT"
fi

exec python3 -m uvicorn secops.app:app --host "$HOST" --port "$PORT"
