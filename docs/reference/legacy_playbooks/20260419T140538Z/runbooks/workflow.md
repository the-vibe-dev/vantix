# Codex Workflow Runbook (Shared)

## Start
1. `bash ${CTF_ROOT:-.}/scripts/codex-start.sh`
2. Confirm startup read order was followed.
3. Validate target health and scope.
4. After large legacy imports or challenge-tree cleanup, run `bash ${CTF_ROOT:-.}/scripts/organize-ctf-data.sh`.

## During Session
1. Write mid-session checkpoints with `bash ${CTF_ROOT:-.}/scripts/codex-close.sh --mode checkpoint ...`.
2. Use `--alias <name>` (optional) and `--agent-id <id>` for parallel-agent continuity.
3. Persist key pivots/artifacts and exact commands.
4. If a checkpoint captures a meaningful new vector or workflow failure, run `bash ${CTF_ROOT:-.}/scripts/learn-ingest.sh`.

## Closeout
1. `bash ${CTF_ROOT:-.}/scripts/codex-close.sh --mode close ...`
2. Ensure handoff includes objective, done work, touched files, blockers, next exact action.
3. Optional explicit handoff write: `--mode handoff`.
4. Auto-learning runs on `handoff`/`close` unless disabled with `--no-learn`.
5. Review `memory/reports/latest_learning_report.md` for new vectors, bugs, guardrails, and pending promotions.

## Resume/Fresh
- Resume: `bash ${CTF_ROOT:-.}/scripts/codex-start.sh` (tries plain `codex resume --last` first).
- After cutover, `memory/session_index.jsonl` is the primary machine-readable continuity source.
- Legacy mirror auto-sync is now only a repair path for true manual/legacy gaps; checkpoint-only index state should not fabricate new handoff entries.
- Startup also reads `memory/session_index.jsonl` and prints latest same-agent and recent cross-session context.
- Fresh: reconstruct from `MEM.md` + latest handoff/journal entries.

## Migration / Cutover
- One-time backfill + inventory refresh: `bash ${CTF_ROOT:-.}/scripts/organize-ctf-data.sh`
- Review cutover state in `memory/reports/migration_cutover_report.md`
- Review session hygiene in `memory/reports/session_inventory.md`
- Use `memory/CUTOVER_STATUS.md` as the current migration status marker
