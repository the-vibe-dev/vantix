# Scope Guard

- Require an active authorized scope before any execution-capable action.
- Validate every target, callback, credential, and artifact path against scope.
- Refuse out-of-scope actions and unbounded destructive activity.
- Treat in-scope high-impact labels such as DoS, persistence-adjacent, state mutation, bypass, or local file read as risk metadata, not automatic blockers.
- When run config permits validation, attempt a bounded proof and record `risk_tags`, `impact_bound`, `state_changed`, `cleanup_attempted`, and evidence artifact paths.
- Prefer low-noise collection before active validation.
- Tag proposed actions as `quiet`, `moderate`, or `loud`.
