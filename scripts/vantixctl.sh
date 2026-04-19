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
RUN_DIR="$RUNTIME_ROOT/run"
mkdir -p "$RUN_DIR"

ACTION="${1:-status}"
SERVICE="${2:-all}"
FORMAT="text"
if [[ "${2:-}" == "--json" ]]; then
  SERVICE="all"
  FORMAT="json"
elif [[ "${3:-}" == "--json" ]]; then
  FORMAT="json"
fi

pid_file() {
  printf '%s/%s.pid\n' "$RUN_DIR" "$1"
}

log_file() {
  printf '%s/%s.log\n' "$RUN_DIR" "$1"
}

is_running() {
  local file pid
  file="$(pid_file "$1")"
  [[ -f "$file" ]] || return 1
  pid="$(cat "$file" 2>/dev/null || true)"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" >/dev/null 2>&1
}

service_pid() {
  local file
  file="$(pid_file "$1")"
  [[ -f "$file" ]] && cat "$file" || true
}

start_one() {
  local name="$1"
  if is_running "$name"; then
    echo "[OK] $name already running pid=$(service_pid "$name")"
    return 0
  fi
  case "$name" in
    api)
      nohup bash "$ROOT_DIR/scripts/secops-api.sh" >"$(log_file api)" 2>&1 &
      ;;
    ui)
      nohup bash "$ROOT_DIR/scripts/secops-ui.sh" >"$(log_file ui)" 2>&1 &
      ;;
    *)
      echo "unknown service: $name" >&2
      return 2
      ;;
  esac
  echo "$!" >"$(pid_file "$name")"
  echo "[OK] started $name pid=$! log=$(log_file "$name")"
}

stop_one() {
  local name="$1" pid file
  file="$(pid_file "$name")"
  if ! is_running "$name"; then
    rm -f "$file"
    echo "[OK] $name stopped"
    return 0
  fi
  pid="$(cat "$file")"
  kill "$pid" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      rm -f "$file"
      echo "[OK] stopped $name"
      return 0
    fi
    sleep 0.25
  done
  kill -9 "$pid" >/dev/null 2>&1 || true
  rm -f "$file"
  echo "[WARN] force-stopped $name"
}

status_text() {
  local name="$1" pid
  pid="$(service_pid "$name")"
  if is_running "$name"; then
    echo "$name running pid=$pid log=$(log_file "$name")"
  else
    echo "$name stopped log=$(log_file "$name")"
  fi
}

status_json() {
  local api_running=false ui_running=false api_pid="" ui_pid=""
  if is_running api; then api_running=true; api_pid="$(service_pid api)"; fi
  if is_running ui; then ui_running=true; ui_pid="$(service_pid ui)"; fi
  printf '{"managed":true,"run_dir":"%s","services":{"api":{"running":%s,"pid":"%s","log":"%s"},"ui":{"running":%s,"pid":"%s","log":"%s"}}}\n' \
    "$RUN_DIR" "$api_running" "$api_pid" "$(log_file api)" "$ui_running" "$ui_pid" "$(log_file ui)"
}

for_each_service() {
  local action="$1" target="$2"
  if [[ "$target" == "all" ]]; then
    "$action" api
    "$action" ui
  else
    "$action" "$target"
  fi
}

case "$ACTION" in
  start)
    for_each_service start_one "$SERVICE"
    ;;
  stop)
    for_each_service stop_one "$SERVICE"
    ;;
  restart)
    for_each_service stop_one "$SERVICE"
    for_each_service start_one "$SERVICE"
    ;;
  status)
    if [[ "$FORMAT" == "json" ]]; then
      status_json
    else
      for_each_service status_text "$SERVICE"
    fi
    ;;
  *)
    echo "usage: $0 start|stop|restart|status [api|ui|all] [--json]" >&2
    exit 2
    ;;
esac
