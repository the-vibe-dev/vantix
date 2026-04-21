# Execution Policy

- Execution-capable skills only propose actions through Vantix approvals and execution controls.
- Commands require timeout/rate-limit defaults and evidence output paths.
- No blind piping into shells, `eval`, target-controlled substitutions, or unbounded destructive changes.
- In-scope high-impact validation is permitted when bounded by run policy; record the attempted proof, risk tags, blast-radius limit, state-change status, cleanup status, and artifact path.
- `moderate` and `loud` actions require approval unless run config explicitly permits them.
