# General CTF Playbook

Purpose: fast, repeatable workflow for non-KoTH CTF engagements with durable notes, low-noise early discovery, and explicit recovery steps when VPN/DNS/host behavior is unstable.

This playbook is for authorized lab targets only.

## Goals
- Reach the intended path quickly without skipping deterministic clues.
- Keep tunnel, route, DNS, and artifacts stable enough to survive resets, compaction, or session churn.
- Write durable memory as the engagement progresses, not only at the end.
- Prefer low-noise validation before broad fuzzing or deep brute force.

## Integrity Gate (No Spoilers)
- Active target answers must come from live target evidence only.
- Do not open room-specific walkthroughs, answer posts, or flag-containing content during an active solve.
- If contamination happens, stop immediately, disclose it, invalidate contaminated answers, and re-derive everything from target artifacts.

## Startup Order
1. Read `${CTF_ROOT}/MEM.md`.
2. Read latest `${CTF_ROOT}/memory/compaction_handoffs.md` entry.
3. Read latest `${CTF_ROOT}/memory/session_journal.md` entry.
4. Read relevant sections of `${CTF_ROOT}/PENTEST.md`.
5. If the target is web-facing, load relevant learning lookups:
   - `python3 scripts/learn_engine.py --root ${CTF_ROOT} lookup tag:web --format prompt`
   - add `port:` / `service:` / `cve:` filters as soon as evidence exists.

## Session Setup
1. Start a managed VPN watcher, not a raw OpenVPN process:
   - `bash scripts/vpn-watch-start.sh --ovpn ${CTF_ROOT}/ctf.ovpn`
2. If target IP/ports are unknown, stop there until first recon confirms them.
3. After initial scan confirms current ports, pin the watcher:
   - `bash scripts/vpn-watch-update.sh --target <IP> --ports "22,80,443"`
4. Validate route before touching the target:
   - `ip route get <IP>`
   - Do not assume `tun0` or `tun1`; trust the route table.
5. Run a boot timing gate on freshly spawned/reset targets:
   - wait 90-120 seconds
   - require 2-3 consecutive open checks on required ports before multi-step actions.

## Memory and Artifact Discipline
- Use session-scoped temp storage under `/tmp/CTF/...`.
- At major phase boundaries, sweep volatile artifacts:
  - `bash scripts/tmp-artifact-sweep.sh`
- Write checkpoint/handoff/close entries with:
  - objective
  - completed work
  - files touched
  - blockers
  - next exact action
- Use:
  - `bash scripts/codex-close.sh --mode checkpoint ...`
  - `bash scripts/codex-close.sh --mode handoff ...`
  - `bash scripts/codex-close.sh --mode close ...`

## Recon Flow

### 1. Service Baseline
Run a light first pass:
```bash
nmap -Pn -sC -sV <IP>
```

Immediately after identifying a concrete product/version:
1. build a CVE shortlist
2. run one low-noise exploitability check
3. query the enriched daily intel cache:
   - `curl "http://127.0.0.1:8787/api/v1/cve/intel/search?q=<service_or_cve>" | jq .`
   - `curl "http://127.0.0.1:8787/api/v1/cve/intel/recent?days=7&limit=100" | jq .`
4. if the exploit path is still unclear after 2-3 proof-driven checks, switch to public upstream source research
5. only then move to larger scans or heavier fuzzing

Hard gate: no broad enumeration before the CVE gate is logged.

Version research helper path:
```bash
python3 scripts/service-source-map.py --service "<banner or product string>"
bash scripts/version-research.sh --service "<banner or product string>" --target <IP>
```

### 2. Web Baseline
For every web target:
1. validate DNS path:
   - `cat /etc/resolv.conf`
   - `dig +short <target_domain>`
2. if `.thm` or equivalent lab hostnames do not resolve:
   - add only the base target domain to `/etc/hosts` first
   - add discovered subdomains only after they are validated
   - do not pre-map guessed names because it can hide intended takeover behavior
3. run protocol-split baseline checks:
```bash
curl -skI -H "Host: <domain>" http://<ip>/ | head
curl -skI -H "Host: <domain>" https://<ip>/ | head
```
4. treat HTTP and HTTPS as independent behaviors

### 3. Easy-Path Gate
Before broad fuzzing, spend 5 minutes on deterministic low-noise checks:
- `robots.txt`
- `sitemap.xml`
- view-source / HTML comments
- linked JS/CSS endpoints
- common static roots:
  - `/assets/`
  - `/static/`
  - `/uploads/`
  - `/backup/`
- directory listing
- metadata on directly exposed files

If any concrete clue appears, stop escalation and follow that lead first.

### 4. Vhost/Subdomain Flow
If subdomain or vhost enumeration is needed:
1. test host-header behavior on both `http` and `https`
2. if HTTPS-only vhosts appear, inspect certificates immediately:
```bash
openssl s_client -connect <ip>:443 -servername <vhost> </dev/null 2>/dev/null | \
openssl x509 -noout -subject -issuer -ext subjectAltName
```
3. treat SAN-only hostnames as mandatory next leads
4. add SAN-derived hostnames locally only after discovery
5. retest SAN-derived hosts on both `http` and `https`
6. inspect redirects before further fuzzing

TakeOver lesson:
- `support.futurevera.thm` exposed a SAN-only host
- the flag was on the SAN-derived hostname over `http`, not `https`
- broad fuzzing was wasted time after that clue existed

### 5. Broad Enumeration Trigger
Broad fuzzing is allowed only when:
- easy-path sweep is exhausted or disproven with evidence
- protocol split is recorded
- CVE gate is recorded
- certificate/SAN checks are recorded for relevant HTTPS vhosts

### 6. Stall Recovery Gate (Mandatory)
If 30 minutes pass without new proof-level evidence, or if one exploit path has 2-3 clean failures with no execution proof:
1. stop variant thrashing (payload/port permutations)
2. switch to manual deterministic app-path validation (UI/API flow used by intended exploit chain)
3. define one measurable proof check per attempt (callback hit, file write/readback, new listening socket, auth success)
4. if a concrete product/version is known, run the version research gate before more payload tuning
5. if proof checks remain negative, pivot vector; do not keep tuning the same non-proving path

## Tunnel and Stability Rules
- Use the managed watcher path, not ad-hoc OpenVPN restarts.
- If the target becomes flaky:
  1. stop long-running scans
  2. check watcher state:
     - `.vpn_profile`
     - `.vpn_target`
     - `.vpn_ports`
     - `tail -n 30 ctfvpn_supervisor.log`
  3. revalidate route with `ip route get <IP>`
  4. confirm expected ports are actually up
- Distinguish stale log lines from current watcher config.
- One active polling loop at a time on unstable hosts.

## Room-Type Heuristics

### Web / Takeover
- Base-domain-first hosts mapping.
- Protocol split before assumptions.
- Certificate SAN inspection immediately after HTTPS vhost discovery.
- Redirects and `Location:` headers are first-class evidence.

### Web / XSS Filtered Challenges
- Do context/constraint mapping before payload spray:
  - reflection context (attribute/text/script)
  - exact blocked keywords
  - allowed vs stripped characters
- If `alert` payloads fail but runtime error text is returned, do not mark vector dead.
- If the runtime/checker behavior is stable but unexplained, inspect the public source of the identified framework/app version before brute-forcing more payload families.
- Mandatory pivot set before blocker classification:
  - `prompt("XSS")`
  - `confirm("XSS")`
  - bracket-call variants (`top["al"+"ert"]("XSS")`) when keyword filtering is suspected
- Record one payload per family with result classification (blocked / executed / inconclusive).

### File / Stego / Artifact Challenges
- Run the standard artifact chain:
  - `file`
  - `binwalk`
  - `exiftool`
  - `strings`
  - `foremost`
- Persist pulled artifacts before pivoting.

### Linux Host
- Fast foothold, then local enumeration, then privesc.
- Harvest credential material and SSH keys early if found.
- Preserve any stable access path before deep exploitation.

### Windows Host
- Follow `${CTF_ROOT}/methods/windows/windows_pentest_playbook.md`.
- Prioritize WinRM/SMB/RDP credential paths, then privesc.

## Learning Rules
Record reusable lessons in the memory system when you see:
- a missed easy path
- a DNS/tunnel failure pattern
- a tool bug or unsafe assumption
- a protocol-specific behavior mismatch
- a reusable exploit chain or replay card

Preferred sinks:
- `memory/lessons_learned.md`
- `memory/reports/*.md`
- `learn_engine.py` ingest flow

## Closeout
1. Sweep `/tmp` artifacts:
   - `bash scripts/tmp-artifact-sweep.sh`
2. Run structured close:
```bash
bash scripts/codex-close.sh --mode close --learn \
  --objective "<objective>" \
  --done "<completed>" \
  --files "<files>" \
  --issues "<blockers>" \
  --next "<next exact action>"
```
3. If there is a useful retro, append and ingest it:
   - `bash scripts/learn_from_session.sh <retro-file.md>`

## Non-Negotiables
- Do not skip the route check.
- Do not skip the CVE gate once version evidence exists.
- Do not skip protocol-split testing on web targets.
- Do not skip certificate SAN inspection after HTTPS-only vhost discovery.
- Do not pre-map guessed subdomains into `/etc/hosts`.
- Do not leave learning only in chat context.
- Do not use external answer sources for active targets.
- Do not submit any flag/value that is not observed from the active machine.
