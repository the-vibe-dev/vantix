# Execution Plan (Max 6 Phases)

## Phase 1 - Planning + Workflow Foundations

- Goal:
  - Produce required planning artifacts.
  - Add durable workflow schema/types/errors/checkpoint primitives.
  - Add compatibility-safe workflow scaffolding with no API break.
- Files/modules:
  - `planning/upgrade_plan/*`
  - `secops/models.py`
  - `secops/schemas.py`
  - `secops/services/workflows/{__init__,types,errors,checkpoints}.py` (new)
  - `tests/test_workflow_engine.py` (initial schema/foundation coverage)
- Dependencies:
  - none (additive).
- Migration concerns:
  - `Base.metadata.create_all` must create new tables without touching old data.
- Tests/checks:
  - `pytest -q tests/test_workflow_engine.py tests/test_api.py`
- Commit title:
  - `phase1: add workflow schema foundations and upgrade planning artifacts`

## Phase 2 - Dispatcher + Worker Runtime Skeleton

- Goal:
  - Split API control from worker loop with DB claims and leases.
  - Refactor `ExecutionManager` into enqueue/dispatch compatibility façade.
- Files/modules:
  - `secops/services/execution.py`
  - `secops/services/workflows/{engine,phases,retries}.py` (initial)
  - `secops/services/worker_runtime.py` (new)
  - `secops/routers/system.py` (worker status)
  - `secops/routers/chat.py` and `secops/routers/runs.py` (start/retry/replan integration)
- Dependencies:
  - phase1 models/types.
- Migration concerns:
  - preserve `start/pause/cancel/retry/replan` endpoints.
- Tests/checks:
  - `pytest -q tests/test_api.py tests/test_resume_and_retry.py`
- Commit title:
  - `phase2: refactor execution into durable dispatcher and worker lease skeleton`

## Phase 3 - Idempotent Phases + Retry/Policy Core

- Goal:
  - Implement durable phase handlers with checkpoints and retry classes.
  - Add explicit policy verdict service and safe subprocess wrapper.
- Files/modules:
  - `secops/services/workflows/phases.py`
  - `secops/services/workflows/retries.py`
  - `secops/services/policies.py` (new)
  - `secops/services/execution.py` (adapter integration)
  - new tests for blocked/transient/idempotent/resume.
- Dependencies:
  - phase2 dispatcher/worker runtime.
- Migration concerns:
  - avoid duplicate facts/artifacts on replay.
- Tests/checks:
  - `pytest -q tests/test_phase_handlers.py tests/test_resume_and_retry.py tests/test_api.py`
- Commit title:
  - `phase3: add idempotent phase handlers retries and policy-gated execution`

## Phase 4 - Vector/Chain Intelligence + Reporting

- Goal:
  - Upgrade vector and attack-chain scoring/provenance.
  - Add deterministic reporting synthesis with artifact/event traceability.
- Files/modules:
  - `secops/services/vantix.py`
  - `secops/services/reporting.py` (new)
  - `secops/routers/runs.py`
  - selected panel/API model wiring.
- Dependencies:
  - phase3 normalized phase outputs.
- Migration concerns:
  - keep existing vector/chain payload fields; add additive metadata.
- Tests/checks:
  - `pytest -q tests/test_api.py tests/test_workflow_engine.py`
- Commit title:
  - `phase4: upgrade vector-chain provenance and deterministic reporting`

## Phase 5 - Frontend Operational Visibility

- Goal:
  - Show workflow/phase attempt/blocked/retry/worker state and provenance in UI.
- Files/modules:
  - `frontend/src/api.ts`
  - `frontend/src/App.tsx`
  - targeted panel components.
- Dependencies:
  - phase2+ workflow status APIs and phase4 report metadata.
- Migration concerns:
  - preserve lightweight existing panel architecture.
- Tests/checks:
  - `cd frontend && corepack pnpm build`
- Commit title:
  - `phase5: add workflow and worker operational visibility in frontend`

## Phase 6 - Quality Gates + Docs + Stabilization

- Goal:
  - Strengthen quality tooling, docs, migration notes, and compatibility polish.
- Files/modules:
  - `pyproject.toml`
  - `scripts/check-all.sh`
  - `docs/{architecture,orchestration,testing,workflow_engine,checkpoints,execution_policies,recovery,observability,upgrade_notes}.md`
  - compatibility shims in routers/schemas/services if needed.
- Dependencies:
  - all prior phases.
- Migration concerns:
  - document schema additions and operational startup expectations.
- Tests/checks:
  - targeted backend tests + broader `pytest -q`
  - frontend build
  - `bash scripts/check-all.sh` (best effort).
- Commit title:
  - `phase6: harden quality gates refresh docs and finalize compatibility`
