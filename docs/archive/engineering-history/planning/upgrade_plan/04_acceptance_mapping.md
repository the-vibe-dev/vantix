# Acceptance Checklist Mapping

Source: `planning/upgrade_kit/vantix_upgrade_kit/specs/08_acceptance_checklist.md`

## Architecture

- API process no longer owns long-running execution:
  - `secops/services/execution.py` becomes dispatcher facade.
  - `secops/services/worker_runtime.py` executes claimed phase jobs.
  - Verified by API tests ensuring run can be started and progressed with worker claim records.
- Worker runtime separate and durable:
  - `worker_leases` + workflow tables in `secops/models.py`.
  - worker status surfaced via `/api/v1/system/status`.
- Persisted phase transitions:
  - `WorkflowExecution` + `WorkflowPhaseRun` rows updated per attempt.
- Queryable checkpoints:
  - `RunCheckpoint` latest + history queries; exposed in run graph/status payload.
- Normalized blocked/failed/retry:
  - workflow status fields and retry class enums in workflow types.

## Safety

- Execution policy exists:
  - `secops/services/policies.py`.
- Sensitive actions require approval when configured:
  - policy verdict `require_approval` creates durable `ApprovalRequest`.
- Redacted command logging:
  - safe subprocess wrapper returns redacted stdout/stderr summaries.
- Timeouts/error classes enforced:
  - subprocess wrappers and retry classifier in workflow services.

## Observability

- Worker health endpoint:
  - `/api/v1/system/status` includes worker heartbeat/lease/claimed phase.
- Workflow metrics:
  - `RunMetric` model and updates in engine.
- Phase attempt counts:
  - `WorkflowPhaseRun.attempt` returned by run graph/workflow state endpoint.
- Standardized event types:
  - workflow event emitters use normalized event names.
- Reports include traceable artifacts:
  - reporting service includes references to artifact/fact/event ids.

## Quality

- Ruff/mypy/pyright:
  - configs in `pyproject.toml`; staged strictness.
- Expanded pytest coverage:
  - add `tests/test_workflow_engine.py`, `tests/test_resume_and_retry.py`, `tests/test_phase_handlers.py`.
- Frontend build:
  - `corepack pnpm build` after UI status changes.

## UX

- UI shows workflow/worker status:
  - `frontend/src/App.tsx` + run phase/system panels show workflow and lease health.
- Blocked states explicit:
  - blocked reason + approval required visible in phase/terminal panels.
- Retries/resumes visible:
  - attempt counts, retry badges, resumed indicators.
- Results panel shows phase provenance:
  - include originating phase/attempt/artifact links in run results payload and panel.
