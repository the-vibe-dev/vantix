# Checkpoints

## Purpose

`RunCheckpoint` stores durable per-phase payload snapshots used for resume and audit.

## Semantics

- New checkpoint writes mark prior checkpoint for the same `(run_id, phase_name, checkpoint_key)` as `is_latest=false`.
- Latest checkpoint is queryable via `CheckpointService.get_latest`.
- Historical checkpoints are preserved for phase-attempt history.

## Typical Payload

- phase name and attempt
- status/result summary
- output metadata and resume hint
