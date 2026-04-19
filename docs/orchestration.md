# Vantix Orchestration

Vantix uses a chat-first control plane over the existing run engine. The operator submits an authorized objective, the backend creates or resumes a run, and the scheduler seeds deterministic specialist work so later agents have stable state to consume.

## Runtime Flow

1. `flow-initialization`: normalize target, objective, mode, workspace, and scope context.
2. `recon`: collect service, port, version, and target-shape evidence.
3. `knowledge-load`: load dense memory, prior learning, tool notes, and relevant run history.
4. `vector-store`: rank candidate vectors from memory, manual input, CVE intel, and scheduler output.
5. `research`: query cached CVE and vulnerability-intel data, with live refresh only when explicitly configured.
6. `planning`: store candidate vectors and choose whether deeper recon, development, execution, or reporting is next.
7. `development`: prepare validation helper code, payload notes, or lab reproduction material when evidence supports it.
8. `execution`: run selected vectors through current Codex/script execution controls.
9. `reporting`: assemble findings, artifacts, terminal summary, evidence, and next actions.

## Specialist Roles

| Role | Purpose |
| --- | --- |
| `orchestrator` | Owns phase transitions, run messages, replans, and stop conditions. |
| `recon` | Performs discovery and service enumeration. |
| `knowledge_base` | Loads memory, learning, tool context, and prior cases. |
| `vector_store` | Stores and ranks candidate attack/validation paths. |
| `researcher` | Correlates CVEs, advisories, exploit references, and source intelligence. |
| `developer` | Builds safe validation helpers, payload/lab notes, or exploit-development scaffolding. |
| `executor` | Executes selected vectors under configured approval and execution controls. |
| `reporter` | Produces evidence-backed summaries, artifacts, and operator-ready findings. |

## Chat Behavior

`POST /api/v1/chat` accepts either a new objective with a target or guidance for an existing run.

- New run: target is parsed from `target`, IPv4, URL, hostname, or CIDR-like text. The full message becomes the objective.
- Existing run: the message is stored as a durable run message and mirrored as an operator note, then the scheduler emits a replan event.
- Missing target without `run_id`: rejected with a clear validation error.

## Branching Rules

Vantix v1 seeds deterministic specialist tasks first, then uses run state and operator actions to replan.

- If recon evidence is thin, schedule deeper recon before research.
- If high-confidence CVE/intel matches exist, plan validation before development.
- If a vector needs custom helper code, route to `developer` before `executor`.
- If Codex or scripts are disabled, execution is blocked and the approval/status path is used.
- If a vector fails, store the result, keep evidence, and replan rather than discarding state.
- If no vector is credible, report negative evidence and recommended next collection steps.

## Durable State

The scheduler writes state to SQLAlchemy tables and dense memory:

- `run_messages`: user, orchestrator, agent, and system chat history.
- `tasks` and `agent_sessions`: specialist timeline and workspace paths.
- `run_events`: terminal/timeline/status events.
- `facts` with `kind="vector"`: candidate vectors and selected paths.
- Dense JSONL memory: compact session checkpoints for later retrieval.

## Safety Boundary

Use Vantix only on systems you own or have explicit permission to test. Keep scope, rules of engagement, stop conditions, and client-sensitive context outside committed files. Codex OAuth/runtime remains the default execution path; optional provider APIs are not used unless configured and selected later.
