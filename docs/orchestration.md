# Vantix Orchestration

## Operator Flow

1. Operator sends objective through `/api/v1/chat`.
2. Scheduler seeds run context, tasks, specialist sessions, vectors, and initial notes.
3. Execution manager enqueues durable workflow work (no long-lived API-owned run thread).
4. Worker runtime claims the next runnable phase with a lease.
5. Phase output is persisted; next phase is unlocked; retries/blocked/failure are normalized.

## Durable Phase Sequence

- `context-bootstrap`
- `learning-recall`
- `recon-sidecar`
- `cve-analysis`
- `orchestrate`
- `learn-ingest`
- `report`

Each phase attempt is represented by `WorkflowPhaseRun`. Checkpoints and artifacts remain queryable after process restart.

## Retry/Blocked/Failure Semantics

- Transient classes are retried by creating a new phase attempt.
- Blocked conditions create blocked state and actionable approvals/events.
- Permanent errors mark workflow and run as failed with normalized error metadata.
- Leases are tracked in `WorkerLease` and expired claims can be recovered.

## Safety And Policy Gates

Execution routes evaluate explicit policy verdicts:

- `allow`
- `allow_with_audit`
- `block`
- `require_approval`

Script and codex actions are policy gated and subprocess output is redacted for common secret patterns.

## Planning And Intelligence Outputs

- vectors now include weighted score and provenance metadata.
- attack chains include normalized step contracts:
  - preconditions
  - expected outcome
  - proof required
  - stop conditions
- planning bundle endpoint:
  - `GET /api/v1/runs/{run_id}/planning-bundle`

## Reporting

Report generation is deterministic and writes:

- markdown report: `run_report.md`
- machine summary: `run_report.json`

Both are linked as artifacts with provenance.
