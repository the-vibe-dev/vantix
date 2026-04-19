# Scope Guard

- Require an active authorized scope before any execution-capable action.
- Validate every target, callback, credential, and artifact path against scope.
- Refuse out-of-scope, destructive, persistence, DoS, or bypass actions.
- Prefer low-noise collection before active validation.
- Tag proposed actions as `quiet`, `moderate`, or `loud`.
