# Execution Policies

## Module

`secops/services/policies.py`

## Verdicts

- `allow`
- `allow_with_audit`
- `block`
- `require_approval`

## Evaluated Action Kinds

- `script`
- `codex`

## Subprocess Safety

- timeout support
- structured result record
- stdout/stderr capture
- redaction for common secret patterns

## Operator Impact

Policy blocks/approval requirements are surfaced in run status, events, and approvals so blocked work is actionable.
