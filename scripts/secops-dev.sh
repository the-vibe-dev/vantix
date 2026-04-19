#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "$ROOT_DIR/scripts/lib/load-env.sh"
load_repo_env "$ROOT_DIR"

tmux kill-session -t secopsdev 2>/dev/null || true
tmux new-session -d -s secopsdev "bash '$ROOT_DIR/scripts/secops-api.sh'"
tmux split-window -t secopsdev "bash '$ROOT_DIR/scripts/secops-ui.sh'"
tmux select-layout -t secopsdev even-vertical
tmux attach -t secopsdev
