# Installation

Preferred path:

```bash
bash scripts/install-vantix.sh
```

The installer runs as a normal user, bootstraps `.venv`, writes `.env`, checks Codex/provider readiness, optionally deploys local CVE search + MCP, installs a selected host tool suite, and prepares the frontend/backend.

Run as a normal user. Do not run the application, API, memory writer, or learning pipeline with `sudo`.

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
