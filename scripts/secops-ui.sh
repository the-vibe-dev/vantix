#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "$REPO_ROOT/scripts/lib/load-env.sh"
load_repo_env "$REPO_ROOT"
ROOT_DIR="${SECOPS_FRONTEND_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../frontend" && pwd)}"
cd "$ROOT_DIR"

HOST="${SECOPS_UI_HOST:-0.0.0.0}"
PORT="${SECOPS_UI_PORT:-4173}"

exec corepack pnpm dev --host "$HOST" --port "$PORT" --strictPort
