# KoTH Replay: Fireworks (Linux)

## Target Pattern
- Host profile seen: `21/22/80/9999`
- Web app: Music Gallery (PHP)
- King service rule reminder: do not attack/modify `:9999` service directly

## Winning Chain (Fastest Confirmed)
1. Initial foothold:
   - unauthenticated `save_music` action on `POST /classes/Master.php?f=save_music`
   - upload path under `/uploads/audio/`
2. Command execution:
   - executable upload callback reached at `/uploads/audio/shell_1.php`
   - execution context: `www-data`
3. Privilege escalation:
   - `www-data` can `sudo -u steven` without password
   - `steven` can run `/usr/bin/wget` via sudo without password
4. Root-level write primitives:
   - use root-privileged wget path for controlled root file operations
5. King reclaim:
   - inspect flags first: `lsattr /root/king.txt`
   - if append-only set (`a`), run `chattr -a /root/king.txt` before writing
   - write king, then re-apply protection as needed

## Critical Failure Lessons (What Slowed Reclaim)
- False assumption: only immutable (`i`) mattered on `king.txt`.
- Actual blocker: append-only (`a`) produced `Operation not permitted` even as root.
- Cron fallback consumed time; direct attribute fix (`chattr -a`) was faster and deterministic.
- Near-end local polling can diverge from official final scoreboard; mark end-state as pending until official result confirms.

## Immediate Checklist for Similar Boxes
- `lsattr /root/king.txt` before any repeated write attempts.
- If write fails with `Operation not permitted`:
  - clear both defensively: `chattr -ia /root/king.txt`
  - write king
  - re-apply chosen protection flags.
- Keep a live timestamped king poll log in the final minute and treat scoreboard as final truth.
