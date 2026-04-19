# BMO CTF Checklist (New Approach)

1. Health gate
- VPN up, required target ports stable 2-3 checks.

2. Recon completeness gate
- Full port scan + service versions.
- Web content clues: source, comments, robots, backups, hidden dirs, vhosts.

3. CVE-first mapping
- For each versioned component:
  - `curl \"http://127.0.0.1:5000/api/browse\"`
  - `curl \"http://127.0.0.1:5000/api/browse/<vendor>\"`
  - `curl \"http://127.0.0.1:5000/api/search/<vendor>/<product>\" | jq .`

4. Low-hanging first
- Defaults, obvious creds, reset flows, exposed configs/files.

5. Timebox enforcement
- 20-30 min without new artifact => pivot path.

6. Flag capture discipline
- Record exact retrieval command + output proof per flag.
