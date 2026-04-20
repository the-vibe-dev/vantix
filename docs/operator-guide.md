# Operator Guide

## Run Model

1. Start or continue engagement via UI chat or `POST /api/v1/chat`.
2. Scheduler seeds specialist tasks and phase state.
3. Workflow engine executes phases with policy gates and approvals.
4. Operator reviews activity, vectors, artifacts, and results.
5. Reporter phase writes report artifacts.

## UI Workflow

- Select module/mode and target.
- Send objective in Mission Chat.
- Watch phase progression, Agent Team status, and Live Activity.
- Approve or reject gated actions when prompted.
- Review Intel, vectors, results, and report outputs for the selected run.

## Approval and Scope Discipline

- Keep targets and rules of engagement explicit.
- Approve only actions that match authorization and objective.
- Reject or cancel when scope drifts or evidence is insufficient.
- Use replan messages to adjust direction between phases.

## Browser Assessment (Authorized Web Apps)

The `browser-assessment` phase can capture route discovery, form maps, network summaries, DOM/screenshot artifacts, and session summaries for approved web targets. Authenticated browsing requires explicit run config and approval.

## CVE / Intel Workflow

- Use Intel views and CVE search APIs to enrich service findings.
- Treat intel as hypothesis input until validated against run evidence.
- Prefer low-noise validation before higher-risk actions.

## Reports and Evidence

Report outputs should be built from run artifacts, validated findings, and provenance-linked facts/vectors. Keep operator notes concise and evidence-backed.
