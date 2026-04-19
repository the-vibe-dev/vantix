#!/usr/bin/env bash
set -euo pipefail

DEVWORK_HOST="${DEVWORK_HOST:-<BENCH_HOST>}"
DEVWORK_USER="${DEVWORK_USER:-<CRACK_NODE_USER>}"
SSH_KEY="${SSH_KEY:-~/.ssh/<LAB_KEY>}"
REMOTE_ROOT="${REMOTE_ROOT:-${REMOTE_HOME:-$HOME}/validation-benchmarks}"

if [[ $# -lt 1 ]]; then
  echo "Usage:"
  echo "  $0 <XBEN-XXX-YY>            # launch one benchmark with fixed mapped ports"
  echo "  $0 --stop <XBEN-XXX-YY>     # stop one benchmark"
  echo "  $0 --down-all               # stop all benchmark stacks"
  exit 1
fi

SSH_OPTS=(
  -i "$SSH_KEY"
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o ConnectTimeout=10
)
REMOTE="${DEVWORK_USER}@${DEVWORK_HOST}"

if [[ "${1:-}" == "--down-all" ]]; then
  ssh "${SSH_OPTS[@]}" "$REMOTE" "bash -s" <<'REMOTE_SCRIPT'
set -euo pipefail
ROOT="${REMOTE_ROOT:-${REMOTE_HOME:-$HOME}/validation-benchmarks}"
cd "$ROOT"
for bench in benchmarks/XBEN-*; do
  [[ -d "$bench" ]] || continue
  sudo docker compose -f "$bench/docker-compose.yml" down >/dev/null 2>&1 || true
done
echo "all stopped"
REMOTE_SCRIPT
  exit 0
fi

MODE="up"
BENCH_ID="$1"
if [[ "${1:-}" == "--stop" ]]; then
  MODE="stop"
  BENCH_ID="$2"
fi

ssh "${SSH_OPTS[@]}" "$REMOTE" "REMOTE_ROOT='${REMOTE_ROOT}' BENCH_ID='${BENCH_ID}' MODE='${MODE}' bash -s" <<'REMOTE_SCRIPT'
set -euo pipefail
ROOT="${REMOTE_ROOT:-${REMOTE_HOME:-$HOME}/validation-benchmarks}"
BENCH_ID="${BENCH_ID:?missing benchmark id}"
MODE="${MODE:-up}"
BENCH_DIR="$ROOT/benchmarks/$BENCH_ID"
OVERRIDE="$ROOT/_lan_map/overrides/$BENCH_ID.override.yml"

if [[ ! -d "$BENCH_DIR" ]]; then
  echo "benchmark not found: $BENCH_ID"
  exit 2
fi
if [[ ! -f "$OVERRIDE" ]]; then
  echo "override not found: $OVERRIDE"
  exit 3
fi
if [[ "$MODE" == "stop" ]]; then
  sudo docker compose -f "$BENCH_DIR/docker-compose.yml" -f "$OVERRIDE" down
  exit 0
fi

BUILD_LOG="/tmp/${BENCH_ID}_build.log"
UP_LOG="/tmp/${BENCH_ID}_up.log"
if ! sudo make -C "$BENCH_DIR" build >"$BUILD_LOG" 2>&1; then
  echo "build failed: $BENCH_ID"
  tail -n 80 "$BUILD_LOG" || true
  exit 10
fi
if ! sudo docker compose -f "$BENCH_DIR/docker-compose.yml" -f "$OVERRIDE" up -d >"$UP_LOG" 2>&1; then
  echo "up failed: $BENCH_ID"
  tail -n 80 "$UP_LOG" || true
  exit 11
fi
echo "launched: $BENCH_ID"
REMOTE_SCRIPT
