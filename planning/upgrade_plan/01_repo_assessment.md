# Vantix Repo Assessment (Current State)

## Current Architecture (Observed)

- Backend: FastAPI app in `secops/app.py` with route modules in `secops/routers/`.
- Persistence: SQLAlchemy models in `secops/models.py`, created via `Base.metadata.create_all`.
- Runtime execution:
  - `secops/services/execution.py` has a thread-backed `ExecutionManager`.
  - Phases (`_phase_context`, `_phase_learning`, `_phase_recon`, `_phase_cve`, `_phase_orchestrate`, `_phase_learn_ingest`, `_phase_report`) execute inline in process.
- Chat-first orchestration:
  - `secops/services/vantix.py` bootstraps runs from `/api/v1/chat`.
  - Scheduler seeds specialist tasks/agents/vectors and writes messages/notes.
- Frontend:
  - React SPA in `frontend/src/`.
  - Pull model + SSE stream for events.
  - Strong panel breadth for vectors/chains/approvals/handoff/results.

## Strengths To Preserve

- `/api/v1/chat` workflow is clear and productive.
- Existing run/task/agent/event/fact model is usable and operator-friendly.
- Vectors, attack chains, approvals, handoffs, and notes are already first-class.
- Local user-owned runtime storage via `StorageLayout` is established.
- Existing test suite already checks chat/run/system behavior.

## Weak Areas / Coupling

- API process currently owns long-running phase execution via daemon threads.
- Active run state lives partially in memory (`ExecutionManager._handles`), not fully durable.
- No durable worker lease model; process death can strand phases.
- Retry classes and attempt history are not explicit entities.
- Phase checkpoint data is implicit in task/fact/artifact writes, not normalized.
- Safety gating is ad hoc in phase code (`enable_*` flags and conditional approvals).
- Observability lacks workflow-attempt/lease/metrics primitives.

## Repo-vs-Kit Mismatches

1. Kit assumes explicit workflow modules already exist; repo currently uses:
   - `execution.py` monolith + `phase_state.py`.
2. Kit suggests stronger router split; repo already has broad router surface but no workflow endpoints.
3. Kit assumes migration tooling; repo currently uses create-all startup with no migration framework.
4. Kit references frontend panels not all present by name; repo uses panelized UI but simpler phase data shape.
5. Kit assumes status endpoint with worker readiness; current system endpoint has codex/runtime/tool/install status but no workflow worker lease visibility.

## Key Upgrade Risks

- Breaking `/api/v1/chat` start semantics while moving to durable worker model.
- Changing `RunGraphRead` shape without frontend updates in same phase.
- Duplicate fact/artifact writes if idempotency is not enforced per phase attempt.
- SQLite locking behavior under lease-claim loop if transactions are long.

## Practical Strategy

- Add additive schema and services first.
- Keep existing run tasks/events/facts compatibility while introducing workflow records.
- Convert `ExecutionManager` into dispatcher façade to avoid API contract break.
- Introduce a local in-process worker runtime that is durable-by-DB and restart-safe.
- Migrate phases one-by-one into idempotent handlers with explicit result contracts.
