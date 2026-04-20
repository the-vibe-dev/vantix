# Permissions

The platform is designed for a normal user account. Runtime state defaults to `${XDG_STATE_HOME:-$HOME/.local/state}/ctf-security-ops/...` so it does not require NFS, root-owned mounts, or broad permission repair. Root-owned files in `memory/`, `$SECOPS_RUNTIME_ROOT`, or `artifacts/` can prevent autosave, learning ingest, and API writes.

Check:
```bash
bash scripts/doctor.sh
bash scripts/memory-health.sh
```

Repair project-owned runtime paths only:
```bash
bash scripts/fix-permissions.sh --apply
```

Do not recursively chown parent mounts, `/mnt`, `/var`, `/etc`, or unrelated directories. If privileged setup is needed, perform it separately and return generated data to user-owned paths.
