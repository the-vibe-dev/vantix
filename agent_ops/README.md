# Agent Ops Additions

This folder adds practical controls from the authorized security agent kit to CTF workflow.

## Files
- `config/targets.yaml`: explicit in-scope target declaration.
- `templates/runbook_template.md`: run-time planning and action logging.
- `templates/report_template.md`: final report structure.

## Usage
1. Update `config/targets.yaml` at every room/IP switch.
2. Start each run by copying `runbook_template.md` into `notes/<run_id>.md`.
3. End each run by filling `report_template.md`.
4. Do not execute sensitive/state-changing actions unless target entry is complete and approved.
