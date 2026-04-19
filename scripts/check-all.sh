#!/usr/bin/env bash
set -euo pipefail

python3 -m compileall -q secops scripts/memory-write.py
if command -v ruff >/dev/null 2>&1; then
  ruff check secops tests
fi
if command -v mypy >/dev/null 2>&1; then
  mypy secops/services/workflows secops/services/worker_runtime.py secops/services/policies.py secops/services/reporting.py
fi
if command -v bandit >/dev/null 2>&1; then
  bandit -q -r secops -x tests
fi
pytest -q
find scripts -maxdepth 2 -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
bash scripts/sanitize-check.sh
bash scripts/doctor.sh

if command -v corepack >/dev/null 2>&1 && [[ -f frontend/package.json ]]; then
  (cd frontend && corepack pnpm build)
fi
