# Windows Operator Notes

Use this guide when controlling the workspace from Windows, WSL, or a remote Linux shell.

## Setup
- Clone the repo on a Linux filesystem or WSL path with normal user ownership.
- Configure `.env` from `.env.example`.
- Run `bash scripts/doctor.sh` before starting sessions.

## Startup
```bash
bash scripts/codex-start.sh --print-only
```

## Closeout
```bash
bash scripts/codex-close.sh --mode close --objective "..." --done "..." --next "..."
```

## Paths
Use repo-relative paths or `${CTF_ROOT}`. Do not hard-code private NAS paths or personal Windows paths in tracked docs.

## Windows Targets
- Use `methods/windows/windows_pentest_playbook.md` for Windows assessment flow.
- Use `methods/windows/ad_enumeration.md` for AD enumeration.
- Use `methods/windows/windows_koth.md` for Windows KoTH mechanics.
