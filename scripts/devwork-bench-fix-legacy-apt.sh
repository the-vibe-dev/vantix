#!/usr/bin/env bash
set -euo pipefail

DEVWORK_HOST="${DEVWORK_HOST:-<BENCH_HOST>}"
DEVWORK_USER="${DEVWORK_USER:-<CRACK_NODE_USER>}"
SSH_KEY="${SSH_KEY:-~/.ssh/<LAB_KEY>}"
REMOTE_ROOT="${REMOTE_ROOT:-${REMOTE_HOME:-$HOME}/validation-benchmarks}"

SSH_OPTS=(
  -i "$SSH_KEY"
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o ConnectTimeout=10
)

REMOTE="${DEVWORK_USER}@${DEVWORK_HOST}"

ssh "${SSH_OPTS[@]}" "$REMOTE" "REMOTE_ROOT='${REMOTE_ROOT}' bash -s" <<'REMOTE_SCRIPT'
set -euo pipefail

ROOT="${REMOTE_ROOT:-${REMOTE_HOME:-$HOME}/validation-benchmarks}"
cd "$ROOT"

patched=0
scanned=0

while IFS= read -r -d '' dockerfile; do
  scanned=$((scanned + 1))
  if ! grep -qE 'FROM[[:space:]].*(python:2\.7\.18-slim|slim-buster)' "$dockerfile"; then
    continue
  fi
  if grep -q 'archive.debian.org' "$dockerfile"; then
    continue
  fi

  python3 - "$dockerfile" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = "RUN apt-get update"
inject = (
    "RUN sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g; "
    "s|security.debian.org/debian-security|archive.debian.org/debian-security|g; "
    "s|buster-updates|buster|g' /etc/apt/sources.list "
    "&& printf 'Acquire::Check-Valid-Until \"false\";\\n"
    "Acquire::AllowInsecureRepositories \"true\";\\n"
    "Acquire::AllowDowngradeToInsecureRepositories \"true\";\\n' "
    "> /etc/apt/apt.conf.d/99archive && apt-get update"
)
if needle not in text:
    sys.exit(0)
text = text.replace(needle, inject, 1)
path.write_text(text, encoding="utf-8")
PY
  patched=$((patched + 1))
  echo "patched: $dockerfile"
done < <(find benchmarks -type f -name Dockerfile -print0)

echo "scanned=$scanned patched=$patched"
REMOTE_SCRIPT

