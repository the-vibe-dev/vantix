# Architecture

## Layers

- UI: React/Vite dashboard in `frontend/`.
- API: FastAPI routers in `secops/routers/`.
- Persistence: SQLAlchemy models in `secops/models.py`.
- Orchestration: Vantix scheduler and chat services in `secops/services/vantix.py`.
- Skills: registry, selector, prompt assembler, handoff helpers in `secops/services/skills.py` and `agent_skills/`.
- Runtime: Codex/script execution controls in `secops/services/execution.py` and adapters.
- Memory: dense JSONL writer plus DB mirror in `secops/services/memory_writer.py` and `scripts/memory-write.py`.
- CVE/MCP: local CVE APIs and optional MCP server under `secops/mcp/`.

## Request Path

1. UI posts chat to `/api/v1/chat`.
2. `VantixChatService` creates or loads a run and records the operator message.
3. `VantixScheduler` seeds tasks, agents, vectors, events, and memory checkpoints.
4. `SkillApplicationService` applies role/mode/context skills and writes prompts.
5. UI refreshes graph, messages, vectors, results, skills, handoff, and attack chains.

## Storage

Runtime data defaults to:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/ctf-security-ops/<repo-name>-<repo-hash>
```

This keeps generated prompts, handoffs, artifacts, reports, SQLite DBs, and logs under the current user. Shared/NFS storage is optional and should not be required for normal development.

## Internal Names

The Python package and many env vars still use `secops` for compatibility. Product-facing docs and UI should use Vantix. A deep rename should be a separate migration after API and DB compatibility are planned.
