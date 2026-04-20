# Release Signing and Verification

Vantix releases are signed with [cosign](https://github.com/sigstore/cosign)
using GitHub's keyless OIDC flow. There are no long-lived signing keys — each
release tag produces a short-lived certificate bound to the CI workflow
identity.

## Producing a release

Tag pushes of the form `v*` trigger `.github/workflows/release.yml`:

1. Frontend build (`vite build`).
2. `scripts/build-release.sh` produces `dist/vantix-<version>-<sha>.tar.gz`
   and a sibling `.manifest.json` listing every file's SHA-256.
3. `cosign sign-blob --yes` emits `.sig` and `.pem`.
4. A GitHub Release is created with all four assets attached.

The manifest captures `version`, `git_sha`, and a sorted list of
`{path, sha256, size}` entries. Change anything in the payload and the
manifest stops matching; change the manifest and cosign stops matching.

## Verifying before install

From any machine with `cosign` on PATH:

```
scripts/verify-release.sh /path/to/vantix-<version>-<sha>.tar.gz
```

The script:

1. Runs `cosign verify-blob` against the sibling `.sig`/`.pem`, asserting the
   certificate identity matches `github.com/<org>/<repo>/.github/workflows/release.yml`
   and the OIDC issuer is GitHub Actions.
2. Extracts the tarball to a temp dir.
3. Walks the manifest and confirms every file's SHA-256 matches.

Override the expected identity via `VANTIX_SIG_IDENTITY_REGEXP` when verifying
a fork. Use `--skip-cosign` only when auditing an already-extracted payload
(manifest check only, not a chain of custody).

## NAS bootstrap integrity

`InstallerStateService.verify_release_integrity` records the running release's
`git_sha` + manifest digest on first boot under
`<runtime_root>/install/installer_state.json`. Subsequent boots compare against
the recorded fingerprint. If they diverge, the service refuses to proceed until
the operator acknowledges the change:

```
VANTIX_ACCEPT_VERSION_CHANGE=<new-git-sha> systemctl restart vantix-secops
```

This is the last line of defense against silent tampering of deployed state —
it won't catch a tamper that also rewrites the state file, but an attacker
with write access to the NAS needs both fingerprints and timing to be silent.

## Ollama runtime bootstrap

`curl | sh` was removed from the provider runtime bootstrap. The installer now
downloads the Ollama install script over TLS, hashes it, compares against
`SECOPS_OLLAMA_INSTALL_SHA256`, and only then executes. Update the pinned
digest after reviewing upstream script changes:

```
curl -fsSL https://ollama.com/install.sh | sha256sum
```

Set the resulting hex digest in your environment (or `.env`) as
`SECOPS_OLLAMA_INSTALL_SHA256=<digest>` before triggering a runtime install.
