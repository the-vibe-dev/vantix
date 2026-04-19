# Upgrade Kit Inventory

This inventory covers every file shipped in `vantix_upgrade_kit.zip` and maps each prompt/spec to concrete Vantix modules in this repository.

## Zip File List And Summary

1. `vantix_upgrade_kit/README.md`
   - Purpose and upgrade outcome targets (durable, safer, modular, resumable).
2. `vantix_upgrade_kit/NOTICE.md`
   - Original-work notice and no-verbatim-copy guidance.
3. `vantix_upgrade_kit/specs/01_gap_analysis.md`
   - Strengths/weaknesses analysis; durable orchestration and observability gaps.
4. `vantix_upgrade_kit/specs/02_transplant_map.md`
   - Shannon/PentAGI/Strix pattern transplant map.
5. `vantix_upgrade_kit/specs/03_target_architecture.md`
   - Target control-plane/workflow/worker/adapters/audit shape.
6. `vantix_upgrade_kit/specs/04_prioritized_backlog.md`
   - High-level six-part delivery sequence.
7. `vantix_upgrade_kit/specs/05_file_impact_map.md`
   - Suggested touched files/new modules.
8. `vantix_upgrade_kit/specs/06_testing_strategy.md`
   - Unit/workflow/integration/frontend quality checks.
9. `vantix_upgrade_kit/specs/07_docs_to_add.md`
   - Required docs pages for upgraded runtime.
10. `vantix_upgrade_kit/specs/08_acceptance_checklist.md`
    - Architecture/safety/observability/quality/UX acceptance.
11. `vantix_upgrade_kit/specs/09_build_order.md`
    - Ordered prompt execution guidance.
12. `vantix_upgrade_kit/source_maps/vantix_files_reviewed.md`
    - Candidate Vantix files previously reviewed by kit author.
13. `vantix_upgrade_kit/source_maps/external_repo_reference_map.md`
    - External inspiration map and no-copy reminder.
14. `vantix_upgrade_kit/codex_prompts/01_workflow_engine_foundation.txt`
    - Workflow subsystem, durable transitions, refactor execution manager.
15. `vantix_upgrade_kit/codex_prompts/02_schema_and_checkpoints.txt`
    - Add workflow/checkpoint/lease/metrics entities.
16. `vantix_upgrade_kit/codex_prompts/03_worker_runtime_split.txt`
    - API enqueue + worker claim/lease loop.
17. `vantix_upgrade_kit/codex_prompts/04_phase_handlers_and_retries.txt`
    - Idempotent phases, retry classes, resume behavior.
18. `vantix_upgrade_kit/codex_prompts/05_execution_policies_and_safety.txt`
    - Policy verdicts, redaction, subprocess hardening.
19. `vantix_upgrade_kit/codex_prompts/06_vector_and_attack_chain_upgrade.txt`
    - Better ranking/provenance/planning bundle.
20. `vantix_upgrade_kit/codex_prompts/07_reporting_and_result_synthesis.txt`
    - Deterministic evidence-backed report synthesis.
21. `vantix_upgrade_kit/codex_prompts/08_frontend_operational_visibility.txt`
    - Workflow/worker visibility, retry/blocked status UX.
22. `vantix_upgrade_kit/codex_prompts/09_python_quality_hardening.txt`
    - ruff/mypy/bandit and check flow hardening.
23. `vantix_upgrade_kit/codex_prompts/10_docs_refresh.txt`
    - Architecture/runtime docs refresh.
24. `vantix_upgrade_kit/codex_prompts/11_end_to_end_test_pack.txt`
    - Stateful engine, lease, approval, idempotency tests.
25. `vantix_upgrade_kit/codex_prompts/12_final_polish_and_migration.txt`
    - Compatibility shims, startup checks, product coherence.

## Prompt/Spec To Vantix Module Mapping

### Core specs

- Gap/target/transplant/backlog/build-order specs map to:
  - `secops/services/execution.py`
  - `secops/services/vantix.py`
  - `secops/models.py`
  - `secops/routers/chat.py`
  - `secops/routers/runs.py`
  - `secops/routers/system.py`
  - `frontend/src/App.tsx`
  - `frontend/src/api.ts`
  - `docs/architecture.md`, `docs/orchestration.md`, `docs/testing.md`
  - new workflow/worker/policy/report modules under `secops/services/`

### codex_prompts mapping

1. `01_workflow_engine_foundation`:
   - `secops/services/execution.py` (dispatcher)
   - `secops/services/workflows/{types,errors,checkpoints,engine,phases,retries}.py` (new)
   - `secops/services/vantix.py`
2. `02_schema_and_checkpoints`:
   - `secops/models.py`, `secops/schemas.py`, tests.
3. `03_worker_runtime_split`:
   - `secops/services/worker_runtime.py` (new)
   - `secops/services/execution.py`, `secops/routers/system.py`.
4. `04_phase_handlers_and_retries`:
   - `secops/services/workflows/phases.py`
   - `secops/services/workflows/retries.py`
   - execution orchestration integration.
5. `05_execution_policies_and_safety`:
   - `secops/services/policies.py` (new)
   - `secops/services/execution.py` / workflow adapters.
6. `06_vector_and_attack_chain_upgrade`:
   - `secops/services/vantix.py`
   - `secops/services/skills.py`
   - `secops/routers/runs.py`
   - frontend vector/attack-chain panels.
7. `07_reporting_and_result_synthesis`:
   - `secops/services/reporting.py` (new)
   - `secops/routers/runs.py` result/report retrieval.
8. `08_frontend_operational_visibility`:
   - `frontend/src/App.tsx`
   - `frontend/src/api.ts`
   - `frontend/src/components/panels/{RunPhasePanel,TerminalPanel,ResultsPanel}.tsx`.
9. `09_python_quality_hardening`:
   - `pyproject.toml`
   - `scripts/check-all.sh`.
10. `10_docs_refresh`:
   - `docs/{architecture,orchestration,testing}.md`
   - add workflow docs pages.
11. `11_end_to_end_test_pack`:
   - `tests/test_workflow_engine.py` (new)
   - `tests/test_resume_and_retry.py` (new)
   - `tests/test_phase_handlers.py` (new)
   - updates to `tests/test_api.py`.
12. `12_final_polish_and_migration`:
   - compatibility shims across routers/schemas/services
   - migration notes in docs.
