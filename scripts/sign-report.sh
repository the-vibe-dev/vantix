#!/usr/bin/env bash
# P4-3 — sign a Vantix report attestation envelope with cosign.
#
# Usage: scripts/sign-report.sh <path/to/report.attestation.json>
#
# Produces <envelope>.sig and <envelope>.pem alongside the envelope.
# Verifiers recompute the sha256 of each entry in "reports" against the
# files on disk, then run `cosign verify-blob` with the .sig + .pem.
#
# Env:
#   COSIGN_KEY   path to a cosign private key (default: keyless OIDC flow)
#   COSIGN_FLAGS additional flags passed verbatim to cosign
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <report.attestation.json>" >&2
  exit 2
fi

ENVELOPE="$1"
if [[ ! -f "$ENVELOPE" ]]; then
  echo "attestation envelope not found: $ENVELOPE" >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign not installed — install https://github.com/sigstore/cosign" >&2
  exit 1
fi

SIG="${ENVELOPE}.sig"
CERT="${ENVELOPE}.pem"

ARGS=(sign-blob --yes --output-signature "$SIG" --output-certificate "$CERT")
if [[ -n "${COSIGN_KEY:-}" ]]; then
  ARGS+=(--key "$COSIGN_KEY")
fi
# shellcheck disable=SC2086
cosign "${ARGS[@]}" ${COSIGN_FLAGS:-} "$ENVELOPE"

echo "signed: $SIG"
echo "cert:   $CERT"
