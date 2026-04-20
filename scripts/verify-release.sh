#!/usr/bin/env bash
# Verify a signed Vantix release tarball before unpacking it.
#
# Usage:
#   scripts/verify-release.sh <tarball> [--skip-cosign]
#
# Expects sibling files: <tarball>.sig, <tarball>.pem, and <tarball>.manifest.json
# (the manifest can also be named after the unversioned stem — the first
# *.manifest.json next to the tarball is used).
set -euo pipefail

TARBALL="${1:-}"
SKIP_COSIGN=0
if [[ "${2:-}" == "--skip-cosign" ]]; then SKIP_COSIGN=1; fi
if [[ -z "$TARBALL" || ! -f "$TARBALL" ]]; then
  echo "usage: $0 <tarball> [--skip-cosign]" >&2
  exit 2
fi

DIR="$(dirname "$TARBALL")"
BASE="$(basename "$TARBALL" .tar.gz)"
SIG="${TARBALL}.sig"
CERT="${TARBALL}.pem"
MANIFEST="${DIR}/${BASE}.manifest.json"
if [[ ! -f "$MANIFEST" ]]; then
  MANIFEST="$(ls "$DIR"/*.manifest.json 2>/dev/null | head -1 || true)"
fi

if [[ -z "$MANIFEST" || ! -f "$MANIFEST" ]]; then
  echo "manifest not found for $TARBALL" >&2
  exit 1
fi

if [[ "$SKIP_COSIGN" -eq 0 ]]; then
  if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign not on PATH. Install from https://github.com/sigstore/cosign, or rerun with --skip-cosign for manifest-only check." >&2
    exit 1
  fi
  if [[ ! -f "$SIG" || ! -f "$CERT" ]]; then
    echo "signature/certificate missing next to tarball" >&2
    exit 1
  fi
  IDENTITY_REGEXP="${VANTIX_SIG_IDENTITY_REGEXP:-https://github.com/.*/.github/workflows/release.yml@.*}"
  OIDC_ISSUER="${VANTIX_SIG_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
  cosign verify-blob --yes \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --signature "$SIG" \
    --certificate "$CERT" \
    "$TARBALL"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
tar -xzf "$TARBALL" -C "$TMP_DIR"

python3 - "$TMP_DIR" "$MANIFEST" <<'PY'
import json, sys
from pathlib import Path
from secops.release_verify import verify_manifest, VerificationError

root = Path(sys.argv[1])
manifest = json.loads(Path(sys.argv[2]).read_text("utf-8"))
try:
    verify_manifest(root, manifest)
except VerificationError as exc:
    print(f"manifest verify failed: {exc}", file=sys.stderr)
    sys.exit(1)
print("manifest ok")
PY
