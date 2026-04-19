#!/usr/bin/env bash
set -euo pipefail

python3 -m compileall -q secops scripts/memory-write.py
pytest -q
find scripts -maxdepth 2 -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
bash scripts/sanitize-check.sh
bash scripts/doctor.sh

if command -v corepack >/dev/null 2>&1 && [[ -f frontend/package.json ]]; then
  (cd frontend && corepack pnpm build)
fi
