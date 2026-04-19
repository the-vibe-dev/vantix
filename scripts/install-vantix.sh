#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "$ROOT_DIR/scripts/lib/load-env.sh"
load_repo_env "$ROOT_DIR"

BOOT_TOTAL=5
BOOT_STEP=0

print_banner() {
  local art_file="$ROOT_DIR/../drop/vantix.txt"
  if [[ -f "$art_file" ]]; then
    sed -n '1,120p' "$art_file"
  else
    printf '%s\n' '{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}'
    printf '%s\n' '{}888     888     d8888 888b    888 88888888888 8888888 Y88b   d88P {}'
    printf '%s\n' '{}888     888    d88888 8888b   888     888       888    Y88b d88P  {}'
    printf '%s\n' '{}888     888   d88P888 88888b  888     888       888     Y88o88P   {}'
    printf '%s\n' '{}Y88b   d88P  d88P 888 888Y88b 888     888       888      Y888P    {}'
    printf '%s\n' '{} Y88b d88P  d88P  888 888 Y88b888     888       888      d888b    {}'
    printf '%s\n' '{}  Y88o88P  d88P   888 888  Y88888     888       888     d88888b   {}'
    printf '%s\n' '{}   Y888P  d8888888888 888   Y8888     888       888    d88P Y88b  {}'
    printf '%s\n' '{}    Y8P  d88P     888 888    Y888     888     8888888 d88P   Y88b {}'
    printf '%s\n' '{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}'
  fi
  echo
  echo "Vantix installer"
  echo "Use only on systems and targets you own or are explicitly authorized to test."
  echo "This installer can execute tools and write runtime data. Use at your own risk."
  echo "Do not place provider keys, client data, credentials, or private topology in committed files."
}

progress_bar() {
  local current="$1" total="$2" width=28 fill empty
  fill=$((current * width / total))
  empty=$((width - fill))
  printf '['
  printf '%*s' "$fill" '' | tr ' ' '#'
  printf '%*s' "$empty" '' | tr ' ' '-'
  printf '] %s/%s' "$current" "$total"
}

step() {
  BOOT_STEP=$((BOOT_STEP + 1))
  echo
  progress_bar "$BOOT_STEP" "$BOOT_TOTAL"
  echo "  $1"
}

run_cmd() {
  local label="$1"
  shift
  echo "    -> $label"
  printf '       $'
  printf ' %q' "$@"
  echo
  "$@"
}

ensure_pkg() {
  local cmd="$1"
  shift
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "    $cmd: available"
    return 0
  fi
  echo "    $cmd: missing"
  run_cmd "Refresh apt package metadata" sudo apt-get update
  run_cmd "Install bootstrap packages: $*" sudo apt-get install -y "$@"
}

print_banner
step "System prerequisites"
ensure_pkg python3 python3
python3 -m venv --help >/dev/null 2>&1 || ensure_pkg python3-venv python3-venv
python3 -m pip --help >/dev/null 2>&1 || ensure_pkg pip3 python3-pip
command -v git >/dev/null 2>&1 || ensure_pkg git git

step "Python virtual environment"
if [[ ! -x "$ROOT_DIR/.venv/bin/python" ]]; then
  run_cmd "Create .venv" python3 -m venv "$ROOT_DIR/.venv"
else
  echo "    .venv: available"
fi

step "Python packaging"
run_cmd "Upgrade pip" "$ROOT_DIR/.venv/bin/python" -m pip install --upgrade pip

step "Installer dependencies"
run_cmd "Install Vantix editable package" "$ROOT_DIR/.venv/bin/python" -m pip install -e "$ROOT_DIR[dev]"

step "Interactive wizard"
export VANTIX_INSTALLER_BANNER_SHOWN=1
exec "$ROOT_DIR/.venv/bin/python" -m secops.installer --repo-root "$ROOT_DIR" "$@"
