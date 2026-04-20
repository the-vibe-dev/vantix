#!/usr/bin/env bash
# Produce a release tarball and a manifest.json of SHA-256 digests for every
# file inside it. Cosign signing happens in CI (.github/workflows/release.yml);
# this script is the local/CI-shared build step.
#
# Usage:
#   scripts/build-release.sh [--version v1.2.3] [--out dist/] [--dry-run]
set -euo pipefail

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0+unknown")}"
OUT_DIR="dist"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

PKG_NAME="vantix-${VERSION}-${GIT_SHA:0:12}"
TAR_PATH="${OUT_DIR}/${PKG_NAME}.tar.gz"
MANIFEST_PATH="${OUT_DIR}/${PKG_NAME}.manifest.json"
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$OUT_DIR"

# Curate the payload — keep it lean and exclude test/dev/local-only trees.
INCLUDES=(
  secops
  alembic
  alembic.ini
  frontend/dist
  scripts/install-vantix.sh
  pyproject.toml
  docs/operations
)

for path in "${INCLUDES[@]}"; do
  if [[ ! -e "$path" ]]; then
    if [[ "$path" == "frontend/dist" ]]; then
      echo "WARN: $path missing; run \`npm --prefix frontend run build\` first" >&2
      continue
    fi
    echo "missing: $path" >&2
    exit 1
  fi
  target="${STAGE_DIR}/${PKG_NAME}/$(dirname "$path")"
  mkdir -p "$target"
  cp -R "$path" "$target/"
done

# Strip caches that may have slipped in.
find "$STAGE_DIR" -type d \( -name __pycache__ -o -name .mypy_cache -o -name .pytest_cache \) -prune -exec rm -rf {} +

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "dry-run: would package ${PKG_NAME} from:"
  printf '  - %s\n' "${INCLUDES[@]}"
  exit 0
fi

(cd "$STAGE_DIR" && tar -czf "${ROOT}/${TAR_PATH}" "${PKG_NAME}")

export ROOT STAGE_DIR PKG_NAME VERSION GIT_SHA STAMP MANIFEST_PATH
python3 - <<PY
import hashlib, json, os, sys
from pathlib import Path

root = Path(os.environ["ROOT"])
stage = Path(os.environ["STAGE_DIR"]) / os.environ["PKG_NAME"]
files = []
for p in sorted(stage.rglob("*")):
    if not p.is_file():
        continue
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    rel = p.relative_to(stage).as_posix()
    files.append({"path": rel, "sha256": digest, "size": p.stat().st_size})

manifest = {
    "version": os.environ["VERSION"],
    "git_sha": os.environ["GIT_SHA"],
    "created_at": os.environ["STAMP"],
    "package": os.environ["PKG_NAME"],
    "files": files,
}
out = root / os.environ["MANIFEST_PATH"]
out.write_text(json.dumps(manifest, indent=2, sort_keys=True))
print(f"manifest: {out}")
PY

echo "tarball: ${TAR_PATH}"
echo "manifest: ${MANIFEST_PATH}"
