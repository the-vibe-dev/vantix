#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$ROOT_DIR"
patterns=(
  'BEGIN OPENSSH PRIVATE KEY'
  'BEGIN RSA PRIVATE KEY'
  'BEGIN EC PRIVATE KEY'
  'ANTHROPIC_API_KEY=.*[^[:space:]]'
  'OPEN_AI_KEY=.*[^[:space:]]'
  'GEMINI_API_KEY=.*[^[:space:]]'
)
if [[ -n "${SANITIZE_DENY_EXTRA:-}" ]]; then
  while IFS= read -r pat; do
    [[ -n "$pat" ]] && patterns+=("$pat")
  done <<<"$SANITIZE_DENY_EXTRA"
fi
if [[ -f ".sanitize-deny.local" ]]; then
  while IFS= read -r pat; do
    [[ -n "$pat" && "$pat" != \#* ]] && patterns+=("$pat")
  done < ".sanitize-deny.local"
fi
status=0
for pat in "${patterns[@]}"; do
  if rg -n --glob '!tools/**' --glob '!frontend/pnpm-lock.yaml' --glob '!memory/local/**' --glob '!scripts/sanitize-check.sh' --glob '!*.pyc' "$pat" . >/tmp/secops_sanitize_hits.$$ 2>/dev/null; then
    echo "[FAIL] private pattern found: $pat" >&2
    cat /tmp/secops_sanitize_hits.$$ >&2
    status=1
  fi
done
rm -f /tmp/secops_sanitize_hits.$$
exit "$status"
