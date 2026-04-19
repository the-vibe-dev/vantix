#!/usr/bin/env bash

load_repo_env() {
  local root="${1:-}"
  [[ -n "$root" ]] || return 0
  local env_file="$root/.env"
  [[ -f "$env_file" ]] || return 0
  set -a
  # shellcheck disable=SC1090
  source "$env_file"
  set +a
}
