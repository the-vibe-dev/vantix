# Getting Started

## Install

Preferred path:

```bash
bash scripts/install-vantix.sh
```

This installs backend/frontend dependencies, prepares `.env`, runs readiness checks, and can configure service management.

## Start / Stop Services

Repo-local controller:

```bash
bash scripts/vantixctl.sh start
bash scripts/vantixctl.sh status
bash scripts/vantixctl.sh restart
bash scripts/vantixctl.sh stop
```

If you enabled user-level systemd services during install:

```bash
systemctl --user status vantix-api.service vantix-ui.service
journalctl --user -u vantix-api.service -u vantix-ui.service -f
```

## Manual Setup (No Installer)

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
.venv/bin/python -m playwright install chromium
cp .env.example .env
bash scripts/doctor.sh
```

Frontend:

```bash
cd frontend
corepack pnpm install
corepack pnpm dev
```

Browser runtime note:

- `scripts/install-vantix.sh` and `scripts/update-vantix.sh` already install Playwright Chromium.
- Manual installs must run `.venv/bin/python -m playwright install chromium` or browser assessment will stay in degraded mode.

## Verify

```bash
curl -s http://127.0.0.1:8787/api/v1/system/status
```

## Users and Login

- First install/boot can seed users from `.env`:
  - `SECOPS_ADMIN_USERNAME`
  - `SECOPS_ADMIN_PASSWORD`
  - optional `SECOPS_BOOTSTRAP_USERS` (`username:password:role,...`)
- Manage users locally with:

```bash
bash scripts/vantix-user.sh list
bash scripts/vantix-user.sh upsert --username admin --password 'change-me' --role admin
bash scripts/vantix-user.sh set-password --username admin --password 'new-password'
```

## Update

```bash
bash scripts/update-vantix.sh --check
bash scripts/update-vantix.sh
bash scripts/update-vantix.sh --verify
```

Use `--no-restart` if you want dependency refresh without restarting managed services.
