# Methods Index

Reusable method bundles for CTF/pentest sessions.

## Directories

- `ics_plant/`
  - Modbus/ICS helpers for TryHackMe plant rooms.
  - Includes safer throttled attack loops and `requirements.txt`.

- `sqli_resumable_wordpress/`
  - Resumable SQLi extraction workflow for unstable targets.
  - Includes VPN stale-guard and tmux orchestration scripts.

- `thm_general/`
  - General TryHackMe room prep helpers.
  - Includes `start_bmo_ctf.sh`, `bmo_ctf_checklist.md`, and `koth_playbook.md`.

## CVE Research Method (Service-backed)

The CVE lookup method is backed by local `cve-search` in:
- `${CTF_ROOT}/tools/cve-search`

Use this endpoint pattern from agents:
```bash
LAN_IP=$(hostname -I | awk '{print $1}')
curl "http://${LAN_IP}:5000/api/browse"
curl "http://${LAN_IP}:5000/api/browse/<vendor>"
curl "http://${LAN_IP}:5000/api/search/<vendor>/<product>" | jq .
```

## Operational Rules

1. Always run health gate first (`/api/` should return 200).
2. Treat `/api/browse` 500 as bootstrap/loading state until initial import finishes.
3. Use daily timer updates; avoid repeated full repopulates unless DB is corrupted/outdated.
4. Keep target actions serialized when tunnel/host is unstable.
