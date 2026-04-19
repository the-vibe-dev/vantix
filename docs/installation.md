# Installation

Preferred path:

```bash
bash scripts/install-vantix.sh
```

The installer runs as a normal user, bootstraps `.venv`, writes `.env`, checks Codex/provider readiness, optionally deploys local CVE search + MCP, installs a selected host tool suite, and prepares the frontend/backend.

Run as a normal user. Do not run the application, API, memory writer, or learning pipeline with `sudo`.

The installer prints embedded Vantix ASCII art, uses `../drop/vantix.txt` as an optional override when present, shows explicit safety warnings, and reports progress for bootstrap, backend, frontend, CVE, tool-suite, verification, and service-startup phases. Long-running package and build commands are shown with their command line and live output so failures are actionable. If the configured CVE API is already reachable, the installer reuses it instead of starting another local cve-search process.

## Service Startup

During installation you can choose user-level systemd services for the API and UI. This writes units under `~/.config/systemd/user/` and runs Vantix as the installing user:

```bash
systemctl --user status vantix-api.service vantix-ui.service
journalctl --user -u vantix-api.service -u vantix-ui.service -f
```

If you enable and start services during install, the API and UI are managed by systemd. The installer can also attempt `loginctl enable-linger "$USER"` when you want user services to start at boot without an active login. If linger is not enabled, services still work while the user systemd manager is running.

If you skip systemd, use the repo-local service controller:

```bash
bash scripts/vantixctl.sh start
bash scripts/vantixctl.sh status
bash scripts/vantixctl.sh restart
bash scripts/vantixctl.sh stop
```

Manual path:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
cp .env.example .env
bash scripts/doctor.sh
```

Optional frontend:
```bash
cd frontend
pnpm install
pnpm dev
```

If you skip the installer, system packages can still be installed separately with your package manager. In the new installer-managed flow, Vantix can install allowlisted host tools on Debian-family systems when selected during install or through the tool API.

## Updating

Do not rerun the interactive installer for normal GitHub updates. Use the updater:

```bash
bash scripts/update-vantix.sh --check
bash scripts/update-vantix.sh
bash scripts/update-vantix.sh --verify
```

The updater:
- fetches `origin/main`
- blocks if the working tree has local non-ignored changes
- fast-forwards only
- snapshots `.env` and installer state
- refreshes Python and frontend dependencies
- rebuilds the frontend
- verifies runtime readiness
- restarts services that were launched through `bash scripts/vantixctl.sh start`

Repo-local managed service commands:

```bash
bash scripts/vantixctl.sh start
bash scripts/vantixctl.sh status
bash scripts/vantixctl.sh restart
bash scripts/vantixctl.sh stop
```

If services were started manually, restart them manually after an update.

Use `--no-restart` when you want the updater to refresh files and dependencies but leave service lifecycle fully manual.
