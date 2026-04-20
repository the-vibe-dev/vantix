# Operations

1. Confirm authorization and scope in `agent_ops/config/targets.yaml`.
2. Start with `bash scripts/codex-start.sh --print-only`.
3. Run low-noise recon and record evidence.
4. Run CVE/intel lookup when product/version evidence appears.
5. Checkpoint memory at phase boundaries.
6. Close with `bash scripts/codex-close.sh --mode close`.

For KoTH modes, read the active platform rules and keep availability constraints ahead of automation.
