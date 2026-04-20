# Vantix UI

Vantix is the chat-first product shell for this authorized security-operations platform. The UI centers on an orchestrator chat, active run context, specialist timeline, evidence panels, and runtime settings.

## Modules

- `Vantix Recon`: target discovery, service mapping, and initial evidence capture.
- `Vantix Exploit`: vector selection, validation planning, and execution workflow.
- `Vantix Forge`: payload, lab, helper tooling, and exploit-builder workflows.
- `Vantix Report`: findings, evidence, artifacts, and operator-ready summaries.

## Primary Flow

1. Open the frontend.
2. Enter an authorized objective such as `Full test of 10.10.10.10`.
3. The UI posts to `/api/v1/chat`.
4. Vantix creates a run, stores the user message, seeds specialist tasks, and starts the execution manager.
5. The UI streams run events and refreshes messages, target state, vectors, memory, CVE intel, approvals, and results.
6. Additional chat messages on the active run are stored as operator guidance and trigger a replan event.

## Panels

| Panel | Data |
| --- | --- |
| Run Sidebar | Recent runs and active run selection. |
| Orchestrator Chat | Durable run messages and new guidance. |
| Agent Timeline | Specialist tasks and agent-session status. |
| Terminal | Streamed run events and execution output. |
| Target | Target, mode, objective, and scheduler status. |
| Vectors | Candidate vectors, manual insertion, and selection. |
| Memory | Facts and learning hits. |
| CVE Intel | Local CVE/intel search results for the active target. |
| Results | Findings, artifacts, report path, and terminal summary. |
| Approvals | Pending approvals and operator decisions. |
| Runtime Settings | Codex status, API token, and optional provider records. |

## API Token

If `SECOPS_API_TOKEN` is set, paste it into Runtime Settings. The token is stored in browser local storage as `vantix_api_token` and sent as a bearer token for REST calls. Do not use shared browser profiles for sensitive engagements.

## Safety Boundary

Use the UI only for authorized targets. Keep rules of engagement and stop conditions current. Do not enter real provider keys, client data, private topology, SSH keys, or credentials into committed files.
