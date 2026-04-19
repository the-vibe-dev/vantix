# Evidence Rules

- Preserve raw output and parsed conclusions separately.
- Store evidence under the run artifact workspace.
- Use sanitized names: `{tool}_{target}_{timestamp}`.
- Never store secrets, personal keys, private topology, or client data in tracked files.
- Link every finding/vector to evidence or mark it unconfirmed.
