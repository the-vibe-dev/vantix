# Testing Matrix

## Workflow Core

- `tests/test_workflow_engine.py`: schema/checkpoint foundations
- `tests/test_resume_and_retry.py`: claim/lease and stale claim recovery
- `tests/test_phase_handlers.py`: retry classification, blocked normalization, policy redaction
- `tests/test_reporting.py`: deterministic report synthesis

## API Compatibility

- `tests/test_api.py`:
  - chat and scheduler flow
  - blocked orchestration when codex execution is disabled
  - system status and provider handling
  - vectors, attack chains, planning bundle, findings promotion

## Frontend

- `corepack pnpm build` in `frontend/`
