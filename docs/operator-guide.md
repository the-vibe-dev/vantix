# Operator Guide

## Run Model

1. Start or continue engagement via UI chat or `POST /api/v1/chat`.
2. Scheduler seeds initial control-plane state and activates additional specialists as phases become reachable.
3. Workflow engine executes phases with policy gates and approvals.
4. Operator reviews activity, vectors, artifacts, and results.
5. Reporter phase writes report artifacts.

The primary operator loop is now run-centric: mission chat, live timeline, control-center health, approvals, vectors, browser evidence, and report outputs are all scoped to the selected run.

## UI Workflow

- Select module/mode and target.
- Send objective in Mission Chat.
- Watch phase progression, Agent Team activation, Attack Timeline, and Live Activity.
- Approve or reject gated actions when prompted.
- Review Intel, vectors, browser evidence, results, and report outputs for the selected run.

## Approval and Scope Discipline

- Keep targets and rules of engagement explicit.
- Approve only actions that match authorization and objective.
- Reject or cancel when scope drifts or evidence is insufficient.
- Use replan messages to adjust direction between phases.

## Local User Management

- Login users are stored in the local Vantix database, not re-read from `.env` after bootstrap.
- Update/create users with:
  - `bash scripts/vantix-user.sh upsert --username <name> --password '<pass>' --role admin|operator|viewer`
  - `bash scripts/vantix-user.sh set-password --username <name> --password '<pass>'`
  - `bash scripts/vantix-user.sh list`

## Browser Assessment (Authorized Web Apps)

The `browser-assessment` phase can capture route discovery, form maps, network summaries, DOM/screenshot artifacts, session summaries, auth transitions, DOM deltas, client-side signals, and hidden-route hints for approved web targets. Authenticated browsing requires explicit run config and approval.

Use the Browser Assessment panel to review:

- auth/session state and transitions
- blocked browser actions
- observed endpoints
- hidden/admin/debug route hints
- client-side signals
- screenshots and browser artifacts

## CVE / Intel Workflow

- Use Intel views and CVE search APIs to enrich service findings.
- Treat intel as hypothesis input until validated against run evidence.
- Prefer low-noise validation before higher-risk actions.

## Reports and Evidence

Report outputs should be built from run artifacts, validated findings, and provenance-linked facts/vectors. Keep operator notes concise and evidence-backed.
