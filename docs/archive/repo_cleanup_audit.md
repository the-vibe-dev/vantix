# Repo Cleanup Audit

This audit records markdown classification and action during the consolidation pass.

## Canonical Kept / Rewritten

| Original file | Action | Reason |
| --- | --- | --- |
| `README.md` | kept, rewritten | Reduced top-level sprawl; now product entrypoint only. |
| `docs/getting-started.md` | created canonical | Consolidates install, startup, update flow. |
| `docs/operator-guide.md` | created canonical | Consolidates operator workflow, approvals, run controls. |
| `docs/developer-guide.md` | created canonical | Consolidates dev setup, test workflow, script references. |
| `docs/architecture.md` | kept, rewritten | Canonical architecture summary replacing overlapping variants. |
| `docs/workflow-engine.md` | created canonical | Canonical phase/lease/retry engine behavior. |
| `docs/api.md` | kept, rewritten | Canonical API usage and examples. |
| `docs/security-and-safety.md` | created canonical | Canonical authorized-use, policy, permission, secret handling. |
| `docs/local_topology.example.md` | kept | Useful safe example, still referenced by safety docs. |
| `CONTRIBUTING.md` | kept | Standard contributor policy doc. |

## Merged + Archived (Superseded Docs)

All files below were moved to `docs/archive/engineering-history/docs/`:

- `docs/ARCHITECTURE.md`
- `docs/BENCHMARKS.md`
- `docs/QUICKSTART.md`
- `docs/agents.md`
- `docs/browser_agent.md`
- `docs/browser_artifacts.md`
- `docs/browser_authenticated_testing.md`
- `docs/browser_policies.md`
- `docs/checkpoints.md`
- `docs/configuration.md`
- `docs/cracking_nodes.md`
- `docs/cve_mcp.md`
- `docs/development.md`
- `docs/execution_policies.md`
- `docs/installation.md`
- `docs/memory.md`
- `docs/observability.md`
- `docs/operations.md`
- `docs/orchestration.md`
- `docs/permissions.md`
- `docs/platform_architecture.md`
- `docs/providers.md`
- `docs/recovery.md`
- `docs/skill-authoring.md`
- `docs/testing.md`
- `docs/testing_matrix.md`
- `docs/upgrade_notes.md`
- `docs/upstream_feature_matrix.md`
- `docs/vantix_ui.md`
- `docs/worker_runtime.md`

Reason: overlapping content merged into canonical docs; historical details retained for traceability.

## Planning Reclassification

| Original file(s) | Action | Reason |
| --- | --- | --- |
| `planning/browser_agent_upgrade/*` | moved to `docs/archive/engineering-history/planning/browser_agent_upgrade/` | Historical implementation planning. |
| `planning/final_upgrade_pass/*` | moved to `docs/archive/engineering-history/planning/final_upgrade_pass/` | Historical implementation planning. |
| `planning/upgrade_plan/*` | moved to `docs/archive/engineering-history/planning/upgrade_plan/` | Historical implementation planning. |
| `planning/local/README.md` | created | Defines local-only planning workspace. |

## Root Markdown Cleanup

Moved to `docs/archive/engineering-history/root/`:

- `CLONE_SETUP.md`
- `PENTEST.md`
- `SELF_LEARNING_SYSTEM.md`
- `USAGE.md`
- `WINDOWS.md`

Reason: product and operator entry flow should live under canonical docs and README.

## Retained Reference / Method Corpora

Kept unchanged by design:

- `AGENTS.md`, `MEM.md`, `LOOKUP.md`, `CLAUDE.md` (agent/runtime instruction surface)
- `methods/**/*.md` (methodology corpus)
- `agent_skills/**/*.md` (skill pack definitions)
- `review/production_readiness_audit/*.md` (audit artifacts)
- `docs/archive/engineering-history/reference/legacy_playbooks/**` (legacy reference snapshot)
- `tools/cve-search/*.md` (upstream tool documentation)

Reason: these are not primary product docs; they are reference, runtime guidance, or imported corpus material.

## Additional Final Consolidation

| Original file(s) | Action | Reason |
| --- | --- | --- |
| `docs/reference/legacy_playbooks/**` | moved to `docs/archive/engineering-history/reference/legacy_playbooks/**` | Further reduced active `docs/` surface clutter while retaining historical snapshots. |

## Additional Tracking Files

| File | Action | Reason |
| --- | --- | --- |
| `docs/archive/remaining_issues.md` | created | Tracks unresolved product issues outside this doc cleanup scope. |
