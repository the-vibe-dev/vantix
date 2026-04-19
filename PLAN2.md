# Vantix Full Implementation Plan

## Summary

Vantix is the product layer for this authorized offensive-security platform. It should provide a chat-first control plane over the existing FastAPI, SQLAlchemy, React/Vite, dense-memory, CVE-intel, and Codex CLI runtime.

The first full implementation should build a Vantix-branded MVP control plane with real chat-driven orchestration, a specialist-agent scheduler, run visibility, vector/memory/CVE panels, optional provider-key settings, and durable docs. Do not deep-rename the internal Python package from `secops` yet; keep `secops.*` imports stable until the product layer is complete.

Use external reference systems only as clean-room feature inspiration. Do not copy source code from them.

## Implementation Status

Implemented in this pass:

- Durable Vantix chat messages and `/api/v1/chat`.
- Specialist scheduler seed state for orchestrator, recon, knowledge base, vector store, researcher, developer, executor, and reporter.
- Vector/result/status/provider APIs.
- Codex-first Vantix UI with orchestrator chat, run sidebar, timeline, terminal, target, vector, memory, CVE, results, approvals, and runtime settings panels.
- Optional provider config storage with secret-key requirement and no secret disclosure.
- Vantix docs for orchestration, providers, UI, configuration, CVE MCP, and cracking nodes.
- Regression tests for chat, scheduler state, vector selection, provider secrets, and sanitized system status.

Not implemented in v1 by design:

- Deep internal `secops` package/database rename.
- Full multi-user auth/OAuth.
- GraphQL, knowledge graph, observability stack, distributed workers, or automatic provider model routing.

## Product Identity

Use these public names consistently in UI and docs:

- `VANTIX`: overall platform.
- `Vantix Recon`: discovery, enumeration, and target profiling.
- `Vantix Exploit`: validation, exploitation workflow, and vector execution.
- `Vantix Forge`: payload, lab, helper tooling, and exploit-builder workflows.
- `Vantix Report`: findings, evidence, artifacts, and operator-ready summaries.

Keep internal code package names such as `secops`, `SECOPS_*`, and existing database tables for now unless there is a narrow reason to add a Vantix alias. A later migration can do a deep rename once the product behavior is stable.

## Current Baseline

Existing useful foundation:

- FastAPI backend with engagements, runs, tasks, approvals, artifacts, facts, memory, CVE, benchmark, and SSE stream endpoints.
- SQLAlchemy persistence for run state, tasks, actions, agents, events, approvals, facts, memory events, findings, and CVE intel.
- React/Vite frontend with launch form, recent runs, live terminal, task graph, agents, facts, learning, approvals, and notes.
- Dense JSONL memory writer with path compaction and memory health tooling.
- CVE REST endpoints and optional CVE MCP server.
- Codex CLI execution through `CodexRunner`, with Codex OAuth/runtime as default.
- Runtime storage under a user-owned local state directory.

Main gaps:

- No Vantix full UI layout yet.
- No chat endpoint or durable run message model.
- No real specialist-agent scheduler beyond current linear phases.
- No vector candidates/results API for the UI.
- No provider settings API/UI.
- No system status endpoint for Codex/runtime/provider readiness.
- Docs still need a complete Vantix architecture and user guide pass.

## Architecture Target

Vantix should keep this shape:

- Frontend: React/Vite TypeScript, using REST and SSE initially.
- Backend: FastAPI REST API, SQLAlchemy models, existing event stream.
- Runtime: Codex CLI default execution, with optional provider APIs later.
- Memory: dense JSONL as canonical session memory, DB mirror as best-effort index.
- CVE/intel: existing local cache and source adapters, optional MCP exposure.
- Storage: local user-owned runtime root, artifacts in configured output root.

Do not add GraphQL, full auth users, observability stack, Neo4j/Graphiti, or distributed worker services in the first full Vantix implementation unless they are explicitly requested later.

## Backend Implementation

### 1. Chat and Messages

Add durable run messages.

Model:

- Add `RunMessage` table.
- Fields: `id`, `run_id`, `role`, `author`, `content`, `metadata_json`, `created_at`.
- Roles: `user`, `orchestrator`, `agent`, `system`.
- Relationship: `WorkspaceRun.messages`.

Schemas:

- `ChatCreate`: `message`, optional `run_id`, optional `mode`, optional `target`, optional `metadata`.
- `ChatResponse`: `run`, `message`, `started`, `scheduler_status`.
- `RunMessageRead`: all public fields except internal metadata aliases should be normalized as `metadata`.

Routes:

- `POST /api/v1/chat`
  - If `run_id` is absent, parse target and objective from message, create engagement/run, store user message, start scheduler.
  - If `run_id` is present, store user message as operator guidance, add operator note, and trigger scheduler replan/resume.
  - Default mode is `pentest` when not provided unless the target/config indicates another current mode.
- `GET /api/v1/runs/{run_id}/messages`
  - Return ordered messages.

Parsing rules:

- Extract IPv4, URL, hostname, or CIDR-like target from chat when `target` is not supplied.
- Keep the full message as the objective.
- If no target is found, create no run and return a validation error requiring target or active `run_id`.

### 2. Specialist Scheduler

Add `VantixScheduler` service.

Roles:

- `orchestrator`: owns decisions and phase transitions.
- `recon`: runs discovery and service enumeration.
- `knowledge_base`: loads dense memory, learning, tool docs, and prior cases.
- `vector_store`: ranks similar tasks, vectors, and successful patterns from memory/learning data.
- `researcher`: checks CVE/intel, exploit references, and optional source adapters.
- `developer`: prepares exploit, payload, validation helper, or lab reproduction notes.
- `executor`: runs selected vector through Codex/script execution controls.
- `reporter`: produces evidence-backed summary/report.

Scheduler behavior:

- Create or update tasks for these roles in deterministic sequence.
- Create `AgentSession` records for active role work.
- Emit `RunEvent` records for timeline, terminal, decision, vector, memory, CVE, and result updates.
- Write dense memory checkpoints at phase boundaries.
- Use existing `ExecutionManager` phase methods where useful, but introduce branching logic rather than only linear execution.

Default flow:

1. `flow-initialization`: target/objective normalization, scope warning, run manifest.
2. `recon`: low-noise discovery and service facts.
3. `knowledge-load`: dense memory, learning hits, tool guides, prior vectors.
4. `research`: CVE/intel lookup and optional live source refresh when explicitly enabled.
5. `planning`: orchestrator chooses next step and stores candidate vectors.
6. `development`: developer prepares validation/exploit/payload/lab helper only when supported by evidence.
7. `execution`: executor runs selected vector using current execution controls.
8. `reporting`: reporter writes findings, artifacts, evidence, and next actions.

Branching rules:

- If recon has insufficient service/version data, schedule deeper recon before research.
- If CVE/intel has high-confidence matches, schedule validation planning before development.
- If a vector requires custom code or payload generation, schedule developer before executor.
- If Codex/script execution is disabled, mark executor blocked and create approval/status events.
- If execution fails, store result, create approval, and ask orchestrator to replan.
- If no vector is credible, report negative evidence and recommend next recon/research steps.

Do not implement destructive or out-of-scope actions. Preserve the existing authorized-use guardrails.

### 3. Vector and Result APIs

Add vector candidate support.

Preferred v1 storage:

- Store vector candidates as `Fact` rows with `kind="vector"` and structured `metadata_json`.
- Avoid adding a dedicated table unless required by implementation complexity.

Vector shape:

- `id`
- `title`
- `summary`
- `source`: `memory`, `cve`, `research`, `manual`, `scheduler`
- `confidence`
- `severity`
- `status`: `candidate`, `planned`, `executing`, `validated`, `rejected`, `blocked`
- `evidence`
- `next_action`
- `metadata`

Routes:

- `GET /api/v1/runs/{run_id}/vectors`
  - Return vector candidates ordered by confidence/severity/status.
- `POST /api/v1/runs/{run_id}/vectors`
  - Allow manual vector insertion from UI/operator.
- `POST /api/v1/runs/{run_id}/vectors/{vector_id}/select`
  - Mark vector as planned and schedule developer/executor.
- `GET /api/v1/runs/{run_id}/results`
  - Return findings, artifacts, report path, terminal summary, executed vector status, and final run status.

### 4. System Status API

Add `GET /api/v1/system/status`.

Return:

- Product name/version: `Vantix`, package version if available.
- Codex binary availability and configured `SECOPS_CODEX_BIN`.
- `SECOPS_ENABLE_CODEX_EXECUTION`, `SECOPS_ENABLE_SCRIPT_EXECUTION`, `SECOPS_ENABLE_WRITE_EXECUTION`.
- Runtime root and writable status.
- Artifacts root and writable status.
- Memory latest/health summary.
- CVE MCP enabled/path.
- Provider count and default runtime (`codex`).
- Sanitized warnings; never include secrets.

### 5. Provider Settings

Codex OAuth/runtime remains default. Provider keys are optional.

Add provider model/table:

- `ProviderConfig`: `id`, `name`, `provider_type`, `base_url`, `default_model`, `enabled`, `encrypted_secret`, `metadata_json`, `created_at`, `updated_at`.
- Provider types: `openai`, `anthropic`, `gemini`, `ollama`, `bedrock`, `deepseek`, `glm`, `kimi`, `qwen`, `openrouter`, `custom`.

Encryption:

- Use `VANTIX_SECRET_KEY` first, fallback to `SECOPS_SECRET_KEY`.
- If no secret key is configured, provider records can be saved without secret fields, but attempts to store a key must return a clear error.
- Never return decrypted secrets through API.

Routes:

- `GET /api/v1/providers`
- `POST /api/v1/providers`
- `GET /api/v1/providers/{provider_id}`
- `DELETE /api/v1/providers/{provider_id}`
- `POST /api/v1/providers/{provider_id}/test`
  - For v1, this can be a dry connectivity/config validation and may return `not_implemented` for live model calls.

Run selection:

- Do not silently use provider APIs.
- Add optional run config field `provider_id` later; default remains Codex.

### 6. Existing Endpoint Compatibility

Keep current endpoints stable:

- `/api/v1/engagements`
- `/api/v1/runs`
- `/api/v1/tasks`
- `/api/v1/approvals`
- `/api/v1/memory`
- `/api/v1/cve`
- `/api/v1/benchmarks`

Do not break existing tests or shell scripts.

## Frontend Implementation

### 1. Layout

Refactor the frontend from one large `App.tsx` into components.

Required components:

- `VantixShell`: app frame, module navigation, active run context.
- `RunSidebar`: recent runs, launch controls, status badges.
- `OrchestratorChat`: chat input, message history, send/create-run behavior.
- `AgentTimeline`: specialist roles and current scheduler phase.
- `TargetPanel`: target, objective, mode, scope/config.
- `VectorPanel`: candidate vectors, statuses, select action.
- `MemoryPanel`: latest memory and learning hits.
- `CveIntelPanel`: CVE/intel hits and source update affordances.
- `ResultsPanel`: findings, artifacts, report summary.
- `ProviderSettings`: Codex status plus optional provider config forms.
- `TerminalPanel`: streamed terminal/event output.
- `ApprovalPanel`: pending approvals and approve/reject actions.

Keep all components lightweight and local unless routing is introduced later.

### 2. User Flow

Primary flow:

1. User opens Vantix.
2. User types `Full test of 10.10.10.10` in orchestrator chat.
3. UI posts to `/api/v1/chat`.
4. Backend creates run and starts scheduler.
5. UI subscribes to `/api/v1/runs/{run_id}/stream`.
6. Timeline, agents, terminal, vectors, memory, CVE, and results panels update as events arrive.
7. User can add more chat guidance to continue/replan the same run.

If there is no active run and the message has no target, show a validation error in chat.

### 3. API Client

Update `frontend/src/api.ts`:

- Add optional bearer token handling from local storage or user setting.
- Add chat/message/status/provider/vector/results methods.
- Keep current run/task/approval/memory/CVE methods.
- Normalize errors into user-displayable messages.

### 4. Visual Direction

Use a distinctive Vantix look without copying external product UI.

Guidelines:

- Dark operations console.
- Strong header mark: `VANTIX` with compact module labels.
- Role-based colors for Orchestrator, Recon, Researcher, Developer, Executor, Reporter.
- Dense but readable evidence cards.
- Chat should feel central, not an afterthought.
- Terminal output should remain monospace and scrollable.
- Mobile layout should collapse sidebars into stacked panels.

## Documentation Implementation

Update or add:

- `README.md`: Vantix overview, quick start, current capabilities, roadmap link.
- `docs/vantix_ui.md`: UI guide and module definitions.
- `docs/orchestration.md`: scheduler roles, phase flow, branching behavior.
- `docs/providers.md`: Codex-first runtime, optional API provider keys, encryption env vars.
- `docs/configuration.md`: Vantix naming plus existing `SECOPS_*` compatibility note.
- `docs/cve_mcp.md`: Vantix wording where user-facing.
- `docs/cracking_nodes.md`: Vantix wording where user-facing.

Docs must say:

- Use only on systems you own or are authorized to test.
- Codex OAuth/runtime is default to avoid unintended API billing.
- Optional providers are opt-in.
- Do not commit `.env`, provider config, real targets, SSH keys, client data, or topology.

## Testing Plan

### Backend Tests

Add tests for:

- Chat creates a run from a target-bearing message.
- Chat appends to existing run and stores a message/operator note.
- Chat rejects missing target when no run exists.
- Scheduler seeds specialist tasks and agent sessions in expected order.
- Scheduler handles Codex-disabled state without crashing.
- Vector endpoint returns empty array for new run.
- Vector endpoint returns candidates from facts/metadata.
- Results endpoint returns stable empty/default structure for new run.
- Provider API never returns raw secrets.
- Provider API rejects secret storage when encryption key is missing.
- System status redacts sensitive config.

### Frontend Checks

Run:

- `cd frontend && pnpm build`

Manual UI checks:

- Chat launches run from target prompt.
- Active run stream updates timeline/terminal.
- Run selection from sidebar works.
- Vectors panel handles empty and populated states.
- Memory/CVE panels handle empty and populated states.
- Provider settings show Codex default and optional provider status.
- Approval actions still work.
- Layout works on desktop and narrow viewport.

### Regression Checks

Run before handoff:

```bash
pytest -q
find scripts -maxdepth 1 -name '*.sh' -print0 | xargs -0 -n1 bash -n
python3 -m compileall -q secops scripts/memory-write.py
bash scripts/sanitize-check.sh
bash scripts/doctor.sh
```

If frontend dependencies are unavailable, state that `pnpm build` could not be run and why.

## Implementation Order

1. Backend message model and chat route.
2. Scheduler service skeleton with deterministic specialist tasks.
3. System status, vectors, and results endpoints.
4. Frontend API client expansion.
5. Vantix shell and orchestrator chat UI.
6. Agent timeline, vectors, memory, CVE, and results panels.
7. Provider config model/API/UI with encrypted optional keys.
8. Docs update.
9. Tests and validation.

Keep each step independently testable. Do not start broad visual refactors before chat/status endpoints exist.

## Acceptance Criteria

The full Vantix v1 implementation is complete when:

- A user can enter a target/objective in chat and Vantix creates or continues a run.
- The backend records chat messages and specialist scheduler activity durably.
- The UI shows orchestrator chat, specialist agents, task timeline, terminal stream, vectors, memory, CVE intel, approvals, and results.
- Codex OAuth/runtime remains the default execution mechanism.
- Optional provider settings exist and do not leak secrets.
- Existing REST endpoints and tests remain compatible.
- Docs describe Vantix setup, UI, orchestration, providers, and safety boundaries.
- Regression checks pass or any skipped checks are clearly documented.

## Non-Goals For This Plan

- Deep renaming `secops` Python package or database table names.
- Copying external product source code.
- Adding GraphQL as a required API layer.
- Adding full user auth/OAuth login in this pass.
- Adding Neo4j/Graphiti, Langfuse, Grafana, Loki, or distributed worker stacks in this pass.
- Making provider APIs the default execution path.

## Assumptions

- Internal `secops` names remain compatibility implementation details.
- `SECOPS_*` environment variables remain valid for now.
- Vantix branding is public/product-facing.
- Codex CLI is available through `SECOPS_CODEX_BIN` or `PATH` when execution is enabled.
- Current approval behavior remains unchanged unless a later plan explicitly adds stricter gates.

## Implementation Update: Skill Packs, Handoffs, And Attack Chains

Implemented after the initial Vantix MVP:

- Repo-local `agent_skills/` registry with shared scope, evidence, execution, and memory policies.
- 29 compact specialist skill packs for orchestration, recon, web/API, CVE/research, exploit planning, credential-safe review, AD/cloud/mobile/wireless, CTF/forensics/malware analysis, reporting, and defensive social-engineering review.
- `SkillApplicationService` that selects skills by role, mode, keywords, and current facts.
- Prompt assembly into user-owned runtime prompt files under `runs/<workspace>/prompts/`.
- Agent metadata showing selected skills and prompt paths.
- `GET /api/v1/runs/{run_id}/skills` and `POST /api/v1/runs/{run_id}/skills/apply`.
- Dense handoff generation at `GET /api/v1/runs/{run_id}/handoff`, mirrored to `handoffs/current.json`.
- Attack-chain modeling through `GET/POST /api/v1/runs/{run_id}/attack-chains`.
- UI panels for skill packs, handoff status, and attack chains.
- Developer docs for agents, skill authoring, API use, architecture, testing, and contribution workflow.
- `scripts/check-all.sh` for Python/backend/frontend/sanitizer validation.

Next implementation priorities:

1. Split the remaining monolithic `frontend/src/App.tsx` panels into reusable components.
2. Add skill-pack CRUD/reload endpoints for operator-managed local extensions.
3. Add a run-level phase state machine so scheduler branching is explicit and testable.
4. Add evidence/finding promotion from vectors and attack chains into report-ready finding drafts.
5. Add provider routing only after Codex-first execution and approval controls are stable.
