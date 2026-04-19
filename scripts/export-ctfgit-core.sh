#!/usr/bin/env bash
set -euo pipefail

ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DEST_DEFAULT="${CTF_ROOT:-.}Git/CTF"
STAGE_DEFAULT="/tmp/CTF/ctfgit_core_stage"

DEST="$DEST_DEFAULT"
STAGE="$STAGE_DEFAULT"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: export-ctfgit-core.sh [--dest <path>] [--stage <path>] [--dry-run]

Builds a curated CTF core snapshot and mirrors it to destination.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest)
      DEST="${2:-}"
      shift 2
      ;;
    --stage)
      STAGE="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

mkdir -p "$STAGE"
rm -rf "$STAGE"/*

# Root-level files needed for runtime + operator context.
ROOT_FILES=(
  "AGENTS.md"
  "PENTEST.md"
  "MEM.md"
  "README.md"
  "USAGE.md"
  "WINDOWS.md"
  "SELF_LEARNING_SYSTEM.md"
  "pyproject.toml"
  "ctfvpn_loop.sh"
  "CLONE_SETUP.md"
)

# Directories to carry as core runtime.
CORE_DIRS=(
  "scripts"
  "secops"
  "methods"
  "agent_ops"
  "docs"
  "runbooks"
  "tests"
  "memory/learning"
  "tools/cve-search"
  "frontend/src"
)

# Frontend build metadata needed to reinstall dependencies.
FRONTEND_FILES=(
  "frontend/package.json"
  "frontend/pnpm-lock.yaml"
  "frontend/tsconfig.json"
  "frontend/vite.config.ts"
  "frontend/index.html"
)

COPY_ARGS=(-rltD --no-owner --no-group --no-perms)

for file in "${ROOT_FILES[@]}"; do
  [[ -e "$ROOT/$file" ]] || continue
  rsync "${COPY_ARGS[@]}" -R "$ROOT/./$file" "$STAGE/"
done

for dir in "${CORE_DIRS[@]}"; do
  [[ -e "$ROOT/$dir" ]] || continue
  rsync "${COPY_ARGS[@]}" -R "$ROOT/./$dir" "$STAGE/"
done

for file in "${FRONTEND_FILES[@]}"; do
  [[ -e "$ROOT/$file" ]] || continue
  rsync "${COPY_ARGS[@]}" -R "$ROOT/./$file" "$STAGE/"
done

# Strip local runtime clutter/caches from staged tree.
find "$STAGE" -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name "node_modules" -o -name "dist" -o -name ".venv" \) -prune -exec rm -rf {} +
find "$STAGE" -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.log" -o -name ".coverage" -o -name "*.bak" \) -delete

# cve-search should be code-only in clone.
rm -rf "$STAGE/tools/cve-search/.git" \
       "$STAGE/tools/cve-search/.venv" \
       "$STAGE/tools/cve-search/log"

# Drop historical/generated secops outputs from curated clone.
rm -rf "$STAGE/secops/artifacts"

# Minimal memory bootstrap (retain learning corpus, reset journals/indices).
mkdir -p "$STAGE/memory/sessions" "$STAGE/memory/reports"
printf '# Session Journal\n\nUse append-only chronological entries.\n\n## Entry Template\n### YYYY-MM-DD HH:MM TZ\n- Goal:\n- Actions taken:\n- Files changed:\n- Blockers:\n- Next step:\n\n---\n' > "$STAGE/memory/session_journal.md"
printf '# Compaction-Safe Handoffs\n\nWrite short, high-signal handoffs before stopping or when context gets large.\n\n## Handoff Template\n### YYYY-MM-DD HH:MM TZ\n- Current objective:\n- Completed items:\n- Files touched:\n- Unresolved issues:\n- Next exact action:\n\n---\n' > "$STAGE/memory/compaction_handoffs.md"
: > "$STAGE/memory/session_index.jsonl"
: > "$STAGE/memory/sessions/.gitkeep"
: > "$STAGE/memory/reports/.gitkeep"

rsync_args=(-rltD --no-owner --no-group --no-perms --delete --no-times --omit-dir-times)
if [[ "$DRY_RUN" -eq 1 ]]; then
  rsync_args+=(-n --itemize-changes)
fi

echo "[*] Mirroring staged core to: $DEST"
mkdir -p "$DEST"
rsync "${rsync_args[@]}" "$STAGE/" "$DEST/"

echo "[+] Export complete"
echo "    Stage: $STAGE"
echo "    Dest : $DEST"
