# Version-Grounded Source Research

Purpose: turn identified product/version evidence into a bounded research branch before payload thrashing.

Use this when:
- the live target exposes a product/framework/library version,
- the vulnerability class is plausible but exploit detail is weak,
- 2-3 proof-driven checks have failed without a positive signal.

This is normal target research:
- use public upstream repos, release tags, official source packages, docs, changelogs, and patch diffs
- do not use benchmark-local service source during an active black-box benchmark solve

## Minimal Workflow
1. Record target evidence:
   - banner/header/version string
   - route or feature that exposed it
   - suspected bug class
2. Map product -> upstream repo/package:
   ```bash
   python3 scripts/service-source-map.py --service "<banner or product string>"
   ```
3. Build a source research artifact:
   ```bash
   bash scripts/version-research.sh \
     --service "<banner or product string>" \
     --target <IP> \
     --suspected-class "<bug class>"
   ```
4. If repo/ref information is known, clone and diff:
   ```bash
   bash scripts/version-research.sh \
     --service "<banner or product string>" \
     --target <IP> \
     --repo https://github.com/<org>/<repo>.git \
     --ref <observed_tag_or_commit> \
     --suspected-class "<bug class>"

   bash scripts/patchdiff-helper.sh \
     --repo <local_clone_dir> \
     --from <vuln_ref> \
     --to <fixed_ref>
   ```
5. Return to the live target with one bounded hypothesis and one measurable proof check.

## What To Look For

### Web / XSS
- exact reflection sink:
  - tag body
  - attribute value
  - JS string
  - URL-bearing attribute
- runtime checker behavior:
  - which APIs are captured (`alert`, `confirm`, `prompt`)
  - which events are synthesized (`focus`, `mouseover`)
- normalization path:
  - stripped tags
  - stripped characters
  - stripped keywords
  - parser reshaping

### PHP Auth / Session
- `serialize()` / `unserialize()`
- base64-encoded session or auth cookies
- loose comparison (`==`) in auth decisions
- array-vs-string warnings that reveal branch behavior
- privileged state derived from client-controlled data

### SQLi
- exact query composition method
- blacklist/allowlist logic and when it runs
- database engine semantics
- string reconstruction operators and keyword-free expressions

## Evidence Discipline
Every source-derived hypothesis must produce:
- one source citation in the research note
- one live-target proof check
- one outcome classification:
  - success
  - fail
  - inconclusive

If the source suggests a bug but the target does not prove it, pivot quickly.
