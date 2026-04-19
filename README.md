# Vantix

Vantix is a Codex-native offensive-security control plane for authorized CTF, King-of-the-Hill, pentest, bug bounty, CVE-intel, and learning-memory workflows. It runs from a normal user-owned clone directory, stores runtime state under the user profile by default, and does not require NFS, root-owned mounts, or private infrastructure.

## Core Capabilities

- Chat-first Vantix orchestrator for starting or continuing target-scoped runs.
- Specialist scheduler state for Recon, Knowledge Base, Vector Store, Researcher, Developer, Executor, and Reporter roles.
- FastAPI backend with run state, messages, approvals, artifacts, vectors, facts, memory, CVE, provider settings, benchmarks, and SSE stream endpoints.
- React/Vite UI with orchestrator chat, run sidebar, terminal stream, specialist timeline, target context, vector panel, memory/CVE panels, approvals, results, and runtime settings.
- Repo-local skill packs that compact agent prompts by role, mode, and run context.
- Agent handoff and attack-chain APIs for reviewable machine-readable state transfer.
- Dense autosaved memory records for compact session continuity and learning ingestion.
- Local CVE and vulnerability-intel cache with optional MCP server exposure.
- Optional provider records for future model routing; Codex OAuth/runtime remains the default execution mechanism.
- Generic remote cracking-node workflow for operator-owned hashcat workers.

## Quick Start

Interactive installer:

```bash
bash scripts/install-vantix.sh
```

The installer bootstraps the Python environment, frontend dependencies, `.env`, runtime paths, optional provider records, local CVE/MCP deployment, and a selected host tool suite.

Manual bootstrap:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
cp .env.example .env
export SECOPS_API_TOKEN=dev
bash scripts/doctor.sh
bash scripts/secops-api.sh
```

API docs: `http://127.0.0.1:8787/docs`

Frontend:

```bash
cd frontend
corepack pnpm install
corepack pnpm dev
```

Open the UI and enter an authorized objective such as `Full test of 10.10.10.10`. Vantix creates a run, records the chat message, seeds specialist tasks, and streams run state back to the dashboard.

## User Workflow

1. Start the API with `bash scripts/secops-api.sh`.
2. Start the UI with `cd frontend && corepack pnpm dev`.
3. Open the UI and submit a scoped objective in Orchestrator Chat.
4. Review Specialists, Skill Packs, Agent Handoff, Vectors, Memory, CVE Intel, and Results.
5. Select a vector only when the evidence and scope are clear.
6. Add Operator Notes when a run needs human guidance.
7. Use Results and Report artifacts for final review.

For API-only operation, start with:

```bash
curl -s http://127.0.0.1:8787/api/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"Full test of https://example.test","mode":"pentest"}'
```

Use the returned `run.id` for follow-up calls.

## Runtime Model

Generated state defaults to a per-user local state directory:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/ctf-security-ops/<repo-name>-<repo-hash>
```

This avoids SQLite locking issues and root-owned file drift on shared mounts. Reports/artifacts default to `$SECOPS_RUNTIME_ROOT/reports` unless `SECOPS_REPORTS_ROOT` or the legacy `SECOPS_ARTIFACTS_ROOT` alias is set.

| Variable | Purpose |
| --- | --- |
| `SECOPS_REPO_ROOT` | Project root. Defaults to this clone. |
| `SECOPS_RUNTIME_ROOT` | User-owned runtime data. Set this to force a custom local path. |
| `SECOPS_REPORTS_ROOT` | Reports/artifacts root for backend output. |
| `SECOPS_ARTIFACTS_ROOT` | Legacy reports/artifacts alias and shell-script output root. |
| `SECOPS_SHARED_ROOT` | Optional shared storage root. Not required. |
| `VANTIX_SKILLS_ROOT` | Optional override for repo-local skill packs. Defaults to `agent_skills/`. |
| `SECOPS_API_TOKEN` | Bearer token for protected API/MCP routes. |
| `VANTIX_SECRET_KEY` | Preferred encryption key for optional provider secrets. |
| `SECOPS_CODEX_BIN` | Codex CLI binary path/name. |
| `OPERATOR_NAME` | Generic operator label for lab-only workflows. |

Run `bash scripts/doctor.sh` if memory or artifact writes fail. Use `bash scripts/fix-permissions.sh --apply` only for project-owned runtime paths.

## API Highlights

- `POST /api/v1/chat`: create or continue a run from orchestrator chat.
- `GET /api/v1/system/status`: sanitized Codex/runtime/provider readiness.
- `GET /api/v1/system/install-status`: file-backed installer/bootstrap state.
- `GET /api/v1/runs/{run_id}/messages`: durable chat history.
- `GET /api/v1/runs/{run_id}/vectors`: candidate validation/exploit vectors.
- `POST /api/v1/runs/{run_id}/vectors`: insert a manual vector.
- `POST /api/v1/runs/{run_id}/vectors/{vector_id}/select`: mark a vector planned and trigger replan.
- `GET /api/v1/skills`: installed skill-pack catalog.
- `GET /api/v1/runs/{run_id}/skills`: selected skill packs and prompt files per agent.
- `POST /api/v1/runs/{run_id}/skills/apply`: re-run skill selection.
- `GET /api/v1/runs/{run_id}/handoff`: dense run handoff for agent continuation.
- `GET/POST /api/v1/runs/{run_id}/attack-chains`: modeled attack paths for planning/review.
- `GET /api/v1/runs/{run_id}/results`: findings, artifacts, vectors, terminal summary, and report path.
- `GET/POST /api/v1/providers`: optional provider records without secret leakage.
- `GET /api/v1/tools`: registered tool readiness and paths.
- `GET /api/v1/tools/suites`: installable tool suite definitions.
- `POST /api/v1/tools/install`: install or dry-run install allowlisted tools.
- `GET /api/v1/tools/install/history`: recent installer/tool actions.

### Chat Usage

Start a run:

```bash
curl -s http://127.0.0.1:8787/api/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"Full test of 10.10.10.10","mode":"pentest"}'
```

Continue or replan a run:

```bash
curl -s http://127.0.0.1:8787/api/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{"run_id":"<run_id>","message":"Prioritize low-noise web validation and refresh CVE context."}'
```

### Skill Packs

Vantix loads compact skill packs from `agent_skills/` and applies them to each specialist based on role, mode, and current run facts. This keeps agent prompts shorter and makes final notes more machine-readable.

List installed packs:

```bash
curl -s http://127.0.0.1:8787/api/v1/skills
```

Review selected packs for a run:

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/skills
```

Reapply skills after adding notes, vectors, or new facts:

```bash
curl -s -X POST http://127.0.0.1:8787/api/v1/runs/<run_id>/skills/apply
```

Prompt files are written under:

```text
$SECOPS_RUNTIME_ROOT/runs/<workspace_id>/prompts/
```

Skill authoring details are in `docs/skill-authoring.md`.

### Handoffs

The handoff endpoint produces dense continuation state for another agent or session:

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/handoff
```

The same payload is mirrored to:

```text
$SECOPS_RUNTIME_ROOT/runs/<workspace_id>/handoffs/current.json
```

Use this before switching agents, pausing a session, or restarting work.

### Attack Chains

Attack chains model candidate paths without requiring immediate execution.

Create a chain:

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/attack-chains \
  -H 'Content-Type: application/json' \
  -d '{"name":"Recon to validated finding","score":70,"steps":[{"phase":"recon"},{"phase":"validate"}],"notes":"Evidence-backed candidate path."}'
```

List chains:

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/attack-chains
```

### Vectors

Vectors are stored as run facts with `kind="vector"` and are used by the orchestrator to decide what to validate next.

Create a manual vector:

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/vectors \
  -H 'Content-Type: application/json' \
  -d '{"title":"Manual validation path","summary":"operator supplied","confidence":0.8,"next_action":"validate safely"}'
```

Select a vector:

```bash
curl -s -X POST http://127.0.0.1:8787/api/v1/runs/<run_id>/vectors/<vector_id>/select
```

## Memory

Session state is saved as dense JSONL records and mirrored to readable markdown for compatibility.

```bash
bash scripts/codex-start.sh --print-only
bash scripts/codex-close.sh --mode checkpoint --objective "..." --done "..." --next "..."
bash scripts/memory-health.sh
```

The startup wrapper writes a startup checkpoint and can run `scripts/codex-memory-watch.sh` to heartbeat active sessions.

## Dense Codex Context

Codex-facing playbooks now use searchable dense records instead of long explanatory prose. Use lookup commands to load only the slice needed for the current target:

Recon should emit:

```text
focus={mode,tags,ports,svc,versions,cves,phase,role,confidence}
```

Agents should read `LOOKUP.md` first, then query from that focus instead of opening broad context.

```bash
cat LOOKUP.md
python3 scripts/learn_engine.py --root . lookup mode:pentest tag:web service:http --format prompt
python3 scripts/learn_engine.py --root . lookup mode:koth tag:koth --format prompt
python3 scripts/learn_engine.py --root . context mode:windows-ctf tag:ad
```

Dense record format:

```text
id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
```

Verbose pre-conversion references are archived under `docs/reference/legacy_playbooks/<timestamp>/`. Memory mirrors are compacted to dense lines, while full historical copies are archived under `memory/archive/<timestamp>/`.

## CVE REST And MCP

REST endpoints are available under `/api/v1/cve/*` when the API is running.

Repo-local CVE search management:

```bash
bash scripts/secops-cve-search.sh start
bash scripts/secops-cve-search.sh status
bash scripts/secops-cve-search.sh update
```

Enable MCP:

```bash
SECOPS_ENABLE_CVE_MCP=true SECOPS_API_TOKEN=dev bash scripts/secops-api.sh
```

MCP URL: `http://127.0.0.1:8787/mcp/cve`

Use header: `Authorization: Bearer dev`

See `docs/cve_mcp.md`.

## Optional Providers

Codex OAuth/runtime is the default path. Provider API keys are opt-in and are not used silently. To store provider secrets, set `VANTIX_SECRET_KEY` first. See `docs/providers.md`.

## Cracking Nodes

Remote GPU cracking is operator-owned and optional. Copy `agent_ops/config/cracking_nodes.example.yaml` to `agent_ops/config/cracking_nodes.yaml`, fill in your own host, and verify with:

```bash
bash scripts/crack-node-doctor.sh --node gpu-primary
```

See `docs/cracking_nodes.md`.

## Safety

Use only on systems you own or are explicitly authorized to test. Keep scope, rules of engagement, and stop conditions in ignored local configuration. Do not commit `.env`, real client data, target evidence, personal SSH keys, production credentials, provider keys, or private topology.

## Development

```bash
pytest
bash scripts/check-all.sh
bash scripts/sanitize-check.sh
bash scripts/doctor.sh
```

Key docs:

- `PLAN2.md`
- `docs/installation.md`
- `docs/configuration.md`
- `docs/architecture.md`
- `docs/agents.md`
- `docs/skill-authoring.md`
- `docs/api.md`
- `docs/testing.md`
- `docs/orchestration.md`
- `docs/vantix_ui.md`
- `docs/providers.md`
- `docs/permissions.md`
- `docs/memory.md`
- `docs/cve_mcp.md`
- `docs/cracking_nodes.md`
