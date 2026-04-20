from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from secops.services.installer_state import InstallerStateService
from secops.services.tools import ToolService


SERVICE_NAMES = {
    "api": "vantix-api.service",
    "ui": "vantix-ui.service",
}

EMBEDDED_BANNER = r"""
{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}
{}888     888     d8888 888b    888 88888888888 8888888 Y88b   d88P {}
{}888     888    d88888 8888b   888     888       888    Y88b d88P  {}
{}888     888   d88P888 88888b  888     888       888     Y88o88P   {}
{}Y88b   d88P  d88P 888 888Y88b 888     888       888      Y888P    {}
{} Y88b d88P  d88P  888 888 Y88b888     888       888      d888b    {}
{}  Y88o88P  d88P   888 888  Y88888     888       888     d88888b   {}
{}   Y888P  d8888888888 888   Y8888     888       888    d88P Y88b  {}
{}    Y8P  d88P     888 888    Y888     888     8888888 d88P   Y88b {}
{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}
""".strip()


def default_runtime_root(repo_root: Path) -> Path:
    state_home = Path(os.getenv("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    repo_id = hashlib.sha1(str(repo_root).encode("utf-8")).hexdigest()[:8]
    return state_home / "ctf-security-ops" / f"{repo_root.name}-{repo_id}"


def read_env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" not in raw or raw.lstrip().startswith("#"):
            continue
        key, value = raw.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def write_env_file(path: Path, updates: dict[str, str], template_path: Path | None = None) -> None:
    if not path.exists() and template_path and template_path.exists():
        path.write_text(template_path.read_text(encoding="utf-8"), encoding="utf-8")
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(updates)
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if "=" not in line or line.lstrip().startswith("#"):
            out.append(line)
            continue
        key, _ = line.split("=", 1)
        key = key.strip()
        if key in updates:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
            remaining.pop(key, None)
        else:
            out.append(line)
    for key in updates:
        if key not in seen:
            out.append(f"{key}={updates[key]}")
    path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")


def banner_text(repo_root: Path) -> str:
    art_path = repo_root.parent / "drop" / "vantix.txt"
    if art_path.exists():
        return art_path.read_text(encoding="utf-8", errors="ignore").rstrip()
    return EMBEDDED_BANNER


def render_progress_bar(current: int, total: int, *, width: int = 28) -> str:
    total = max(total, 1)
    current = max(0, min(current, total))
    filled = round(width * current / total)
    return f"[{'#' * filled}{'-' * (width - filled)}] {current}/{total}"


def _systemd_quote(value: Path | str) -> str:
    text = str(value)
    if not text or any(char.isspace() or char in {'"', "'", "\\"} for char in text):
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return text


def render_user_systemd_unit(*, description: str, repo_root: Path, script_path: Path) -> str:
    return (
        "[Unit]\n"
        f"Description={description}\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={_systemd_quote(repo_root)}\n"
        f"EnvironmentFile=-{_systemd_quote(repo_root / '.env')}\n"
        f"ExecStart=/usr/bin/env bash {_systemd_quote(script_path)}\n"
        "Restart=on-failure\n"
        "RestartSec=3\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


class Wizard:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self.env_path = self.repo_root / ".env"
        self.env_example = self.repo_root / ".env.example"
        self.venv_python = self.repo_root / ".venv" / "bin" / "python"
        self.env_updates = read_env_file(self.env_path)
        self.runtime_root = Path(self.env_updates.get("SECOPS_RUNTIME_ROOT") or default_runtime_root(self.repo_root))
        self.state = InstallerStateService(self.runtime_root)
        self.tool_service = ToolService(self.repo_root, self.runtime_root)
        self.total_steps = 10
        self.current_step = 0

    def print_intro(self) -> None:
        if os.getenv("VANTIX_INSTALLER_BANNER_SHOWN") == "1":
            return
        print(banner_text(self.repo_root))
        print()
        print("Vantix installer")
        print("Use only on systems and targets you own or are explicitly authorized to test.")
        print("This software can execute tools and write runtime data. Use at your own risk.")
        print("Do not place provider keys, client data, credentials, or private topology in committed files.")

    def section(self, title: str, detail: str = "") -> None:
        self.current_step += 1
        print()
        print(f"{render_progress_bar(self.current_step, self.total_steps)}  {title}")
        if detail:
            print(f"    {detail}")

    def prompt(self, label: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        raw = input(f"{label}{suffix}: ").strip()
        return raw or default

    def confirm(self, label: str, default: bool = True) -> bool:
        suffix = " [Y/n]" if default else " [y/N]"
        raw = input(f"{label}{suffix}: ").strip().lower()
        if not raw:
            return default
        return raw in {"y", "yes"}

    def choose(self, label: str, options: list[str], default: str) -> str:
        rendered = "/".join([item.upper() if item == default else item for item in options])
        raw = input(f"{label} ({rendered}): ").strip().lower()
        return raw if raw in options else default

    def run(self, command: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, check=False, env=env, cwd=cwd or self.repo_root)

    def run_visible(self, command: list[str], *, label: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        start = time.monotonic()
        workdir = cwd or self.repo_root
        print(f"    -> {label}")
        print(f"       $ {' '.join(shlex.quote(part) for part in command)}")
        proc = subprocess.Popen(
            command,
            cwd=workdir,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        lines: list[str] = []
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip()
            if line:
                lines.append(line)
                print(f"       {line}")
        returncode = proc.wait()
        elapsed = time.monotonic() - start
        status = "ok" if returncode == 0 else f"failed rc={returncode}"
        print(f"       [{status}] {elapsed:.1f}s")
        return subprocess.CompletedProcess(command, returncode, "\n".join(lines), "")

    def run_interactive(self, command: list[str], *, label: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        start = time.monotonic()
        workdir = cwd or self.repo_root
        print(f"    -> {label}")
        print(f"       $ {' '.join(shlex.quote(part) for part in command)}")
        proc = subprocess.run(command, cwd=workdir, env=env, check=False, text=True)
        elapsed = time.monotonic() - start
        status = "ok" if proc.returncode == 0 else f"failed rc={proc.returncode}"
        print(f"       [{status}] {elapsed:.1f}s")
        return proc

    def os_info(self) -> dict[str, Any]:
        return self.tool_service.os_info()

    def _apt_sources_configured(self) -> bool:
        sources_paths = [Path("/etc/apt/sources.list"), *Path("/etc/apt/sources.list.d").glob("*.list"), *Path("/etc/apt/sources.list.d").glob("*.sources")]
        for path in sources_paths:
            if not path.exists():
                continue
            for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("deb ") or line.startswith("deb-src ") or line.startswith("URIs:"):
                    return True
        return False

    def _apt_recovery_hint(self) -> str:
        return (
            "echo \"deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware\" "
            "| sudo tee /etc/apt/sources.list\n"
            "sudo apt-get update"
        )

    def _repair_apt_sources(self) -> bool:
        if self._apt_sources_configured():
            return True
        os_info = self.os_info()
        if not os_info.get("kali", False):
            print("    [WARN] APT sources are missing and automatic repair is only enabled for Kali hosts.")
            print("    [HINT] Add package sources, then rerun package install steps:")
            print(self._apt_recovery_hint())
            return False
        print("    [WARN] No APT sources configured. Attempting automatic Kali repository repair.")
        line = "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware"
        proc = self.run_visible(
            ["sudo", "bash", "-lc", f"printf '%s\\n' {shlex.quote(line)} > /etc/apt/sources.list"],
            label="Repair /etc/apt/sources.list for Kali rolling",
        )
        if proc.returncode != 0:
            print("    [WARN] Automatic APT source repair failed.")
            print("    [HINT] Run these commands manually:")
            print(self._apt_recovery_hint())
            return False
        return True

    def ensure_system_packages(self, packages: list[str], *, required: bool = True) -> bool:
        packages = [pkg for pkg in packages if pkg]
        if not packages:
            return True
        missing = []
        for pkg in packages:
            proc = self.run(["bash", "-lc", f"dpkg -s {pkg} >/dev/null 2>&1"])
            if proc.returncode != 0:
                missing.append(pkg)
        if not missing:
            return True
        print(f"    Missing system packages: {' '.join(missing)}")
        if not self._apt_sources_configured() and not self._repair_apt_sources():
            if required:
                raise RuntimeError("APT sources are not configured; cannot install required system packages")
            print("    [WARN] Skipping optional package install because APT sources are unavailable.")
            return False
        update = self.run_visible(["sudo", "apt-get", "update"], label="Refresh apt package metadata")
        if update.returncode != 0:
            repaired = self._repair_apt_sources()
            if repaired:
                update = self.run_visible(["sudo", "apt-get", "update"], label="Retry apt metadata refresh after source repair")
            if update.returncode != 0:
                if required:
                    raise RuntimeError("Failed to refresh apt package metadata")
                print("    [WARN] Skipping optional package install; apt metadata refresh failed.")
                print("    [HINT] Recovery commands:")
                print(self._apt_recovery_hint())
                return False
        proc = self.run_visible(["sudo", "apt-get", "install", "-y", *missing], label=f"Install {' '.join(missing)}")
        if proc.returncode != 0:
            if required:
                raise RuntimeError(f"Failed to install packages: {' '.join(missing)}")
            print(f"    [WARN] Skipping optional package install: {' '.join(missing)}")
            print("    [HINT] Verify apt sources and package availability:")
            print("    apt-cache policy " + " ".join(missing))
            return False
        return True

    def ensure_backend(self) -> None:
        self.ensure_system_packages(["python3", "python3-venv", "python3-pip", "git"], required=True)
        if not self.venv_python.exists():
            proc = self.run_visible(["python3", "-m", "venv", str(self.repo_root / ".venv")], label="Create Python virtual environment")
            if proc.returncode != 0:
                raise RuntimeError("Failed to create Python virtual environment")
        else:
            print(f"    Python virtual environment: {self.venv_python}")
        pip = [str(self.venv_python), "-m", "pip"]
        for command in ([*pip, "install", "--upgrade", "pip"], [*pip, "install", "-e", ".[dev]"]):
            proc = self.run_visible(command, label=" ".join(command[3:]))
            if proc.returncode != 0:
                raise RuntimeError(f"Failed backend bootstrap: {' '.join(command)}")

    def ensure_browser_runtime(self) -> dict[str, Any]:
        pip = [str(self.venv_python), "-m", "pip"]
        playwright_module = self.run([str(self.venv_python), "-m", "playwright", "--version"])
        if playwright_module.returncode != 0:
            install = self.run_visible([*pip, "install", "playwright"], label="Install Playwright Python package")
            if install.returncode != 0:
                return {"enabled": False, "reason": "playwright-install-failed"}
        browser_install = self.run_visible(
            [str(self.venv_python), "-m", "playwright", "install", "chromium"],
            label="Install Playwright Chromium runtime",
        )
        if browser_install.returncode != 0:
            print("    [WARN] Playwright installed but Chromium runtime installation failed.")
            print("    [HINT] Retry manually: .venv/bin/python -m playwright install chromium")
            return {"enabled": False, "reason": "chromium-install-failed"}
        return {"enabled": True, "reason": ""}

    def ensure_corepack(self) -> None:
        if shutil.which("corepack"):
            print("    Corepack: available")
            return
        if not shutil.which("npm"):
            raise RuntimeError("npm is required to install corepack")
        proc = self.run_visible(["sudo", "npm", "install", "-g", "corepack"], label="Install corepack")
        if proc.returncode != 0:
            raise RuntimeError("Failed to install corepack with npm")

    def ensure_frontend(self, build: bool = True) -> dict[str, Any]:
        if not self.ensure_system_packages(["nodejs", "npm"], required=False):
            print("    [WARN] Frontend bootstrap skipped because Node/npm could not be installed.")
            return {"installed": False, "built": False, "skipped_reason": "missing-nodejs-npm"}
        try:
            self.ensure_corepack()
        except RuntimeError as exc:
            print(f"    [WARN] Frontend bootstrap skipped: {exc}")
            return {"installed": False, "built": False, "skipped_reason": "corepack-unavailable"}
        frontend_root = self.repo_root / "frontend"
        proc = self.run_visible(["corepack", "pnpm", "install"], cwd=frontend_root, label="Install frontend dependencies")
        if proc.returncode != 0:
            print("    [WARN] Frontend dependency install failed. Continuing in degraded mode.")
            return {"installed": False, "built": False, "skipped_reason": "frontend-install-failed"}
        built = False
        if build:
            proc = self.run_visible(["corepack", "pnpm", "build"], cwd=frontend_root, label="Build frontend")
            if proc.returncode != 0:
                print("    [WARN] Frontend build failed. Continuing with backend-ready install state.")
                return {"installed": True, "built": False, "skipped_reason": "frontend-build-failed"}
            built = True
        return {"installed": True, "built": built}

    def _merged_env(self) -> dict[str, str]:
        merged = os.environ.copy()
        merged.update(self.env_updates)
        return merged

    def _repo_python(self, code: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        env = self._merged_env()
        if extra_env:
            env.update(extra_env)
        return self.run([str(self.venv_python), "-c", code], env=env)

    def provider_count(self) -> int:
        code = (
            "from secops.db import Base, engine, SessionLocal;"
            "from secops.models import ProviderConfig;"
            "Base.metadata.create_all(bind=engine);"
            "db=SessionLocal();"
            "print(db.query(ProviderConfig).count());"
            "db.close()"
        )
        proc = self._repo_python(code)
        if proc.returncode != 0:
            return 0
        try:
            return int((proc.stdout or "0").strip() or "0")
        except ValueError:
            return 0

    def bootstrap_provider(self, payload: dict[str, Any]) -> None:
        code = (
            "import json, os;"
            "from secops.db import Base, engine, SessionLocal;"
            "from secops.services.providers import ProviderService;"
            "Base.metadata.create_all(bind=engine);"
            "payload=json.loads(os.environ['VANTIX_INSTALLER_PROVIDER']);"
            "db=SessionLocal();"
            "ProviderService(db).upsert(payload);"
            "db.commit();"
            "db.close();"
            "print('ok')"
        )
        proc = self._repo_python(code, {"VANTIX_INSTALLER_PROVIDER": json.dumps(payload)})
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "Provider bootstrap failed").strip())

    def codex_available(self) -> bool:
        configured = self.env_updates.get("SECOPS_CODEX_BIN", "codex")
        return bool(shutil.which(configured) or Path(configured).exists())

    def _codex_main_help(self) -> str:
        if not self.codex_available():
            return ""
        codex_bin = self.env_updates.get("SECOPS_CODEX_BIN", "codex")
        proc = self.run([codex_bin, "--help"])
        return ((proc.stdout or "") + "\n" + (proc.stderr or "")).lower()

    def _codex_subcommand_supported(self, parts: list[str]) -> bool:
        if not self.codex_available():
            return False
        codex_bin = self.env_updates.get("SECOPS_CODEX_BIN", "codex")
        proc = self.run([codex_bin, *parts, "--help"])
        text = ((proc.stdout or "") + "\n" + (proc.stderr or "")).lower()
        if proc.returncode == 0:
            return True
        if "unrecognized subcommand" in text or "unexpected argument" in text:
            return False
        return "usage:" in text

    def ensure_codex_cli(self) -> bool:
        if self.codex_available():
            print("    Codex CLI: available")
            return True
        print("    Codex CLI: missing, attempting install")
        if not self.ensure_system_packages(["nodejs", "npm"], required=False):
            print("    [WARN] Could not install Node/npm, skipping Codex CLI install.")
            return False
        install = self.run_visible(["npm", "install", "-g", "@openai/codex"], label="Install Codex CLI (@openai/codex)")
        if install.returncode != 0:
            install = self.run_visible(["sudo", "npm", "install", "-g", "@openai/codex"], label="Install Codex CLI with sudo")
            if install.returncode != 0:
                print("    [WARN] Codex CLI install failed.")
                print("    [HINT] Try manually: npm install -g @openai/codex")
                return False
        codex_bin = shutil.which("codex")
        if codex_bin:
            self.env_updates["SECOPS_CODEX_BIN"] = codex_bin
        return self.codex_available()

    def codex_device_login(self) -> bool:
        if not self.codex_available():
            return False
        codex_bin = self.env_updates.get("SECOPS_CODEX_BIN", "codex")
        help_text = self._codex_main_help()
        candidates: list[tuple[list[str], str]] = []
        if "--device-auth" in help_text:
            candidates.append(([codex_bin, "--device-auth"], "Sign in Codex CLI (device auth)"))
        if "--login" in help_text:
            candidates.append(([codex_bin, "--login"], "Sign in Codex CLI (login flag)"))
        if self._codex_subcommand_supported(["login"]):
            candidates.append(([codex_bin, "login"], "Sign in Codex CLI (login command)"))
        if self._codex_subcommand_supported(["auth", "login"]):
            candidates.append(([codex_bin, "auth", "login"], "Sign in Codex CLI (auth login command)"))
        if not candidates:
            print("    [WARN] This Codex CLI build does not expose a known interactive login command.")
            print("    [HINT] Either upgrade Codex CLI (`npm install -g @openai/codex`) or export OPENAI_API_KEY in .env.")
            return False
        for command, label in candidates:
            proc = self.run_interactive(command, label=label)
            if proc.returncode == 0:
                return True
        print("    [WARN] Codex login command attempts failed.")
        return False

    def bootstrap_provider_runtime(self, provider_type: str) -> dict[str, Any]:
        provider = (provider_type or "").strip().lower()
        if provider != "ollama":
            return {"provider_type": provider, "runtime_installed": True, "detail": "no local runtime bootstrap required"}
        if shutil.which("ollama"):
            return {"provider_type": provider, "runtime_installed": True, "detail": "ollama already installed"}
        if not self.ensure_system_packages(["curl"], required=False):
            return {
                "provider_type": provider,
                "runtime_installed": False,
                "detail": "curl missing; cannot auto-install ollama",
                "hint": "Install curl and run: curl -fsSL https://ollama.com/install.sh | sh",
            }
        proc = self.run_visible(
            ["bash", "-lc", "curl -fsSL https://ollama.com/install.sh | sh"],
            label="Install Ollama runtime",
        )
        if proc.returncode != 0 or not shutil.which("ollama"):
            return {
                "provider_type": provider,
                "runtime_installed": False,
                "detail": "ollama install failed",
                "hint": "Run manually: curl -fsSL https://ollama.com/install.sh | sh",
            }
        return {"provider_type": provider, "runtime_installed": True, "detail": "ollama installed"}

    def configure_runtime(self) -> None:
        default_runtime = str(self.runtime_root)
        runtime = self.prompt("Runtime root", default_runtime)
        self.runtime_root = Path(runtime).expanduser().resolve()
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        reports_root = self.runtime_root / "reports"
        reports_root.mkdir(parents=True, exist_ok=True)
        database_url = f"sqlite+pysqlite:///{self.runtime_root / 'secops.db'}"
        self.state = InstallerStateService(self.runtime_root)
        self.tool_service = ToolService(self.repo_root, self.runtime_root)
        lan_mode = self.confirm("Expose API/UI on LAN (bind 0.0.0.0)", default=False)
        default_api_host = "0.0.0.0" if lan_mode else self.env_updates.get("SECOPS_HOST", "127.0.0.1")
        default_ui_host = "0.0.0.0" if lan_mode else self.env_updates.get("SECOPS_UI_HOST", "127.0.0.1")
        api_host = self.prompt("API bind host", default_api_host)
        api_port = self.prompt("API port", self.env_updates.get("SECOPS_PORT", "8787"))
        ui_host = self.prompt("UI bind host", default_ui_host)
        ui_port = self.prompt("UI port", self.env_updates.get("SECOPS_UI_PORT", "4173"))
        self.env_updates.update(
            {
                "SECOPS_REPO_ROOT": str(self.repo_root),
                "SECOPS_RUNTIME_ROOT": str(self.runtime_root),
                "SECOPS_REPORTS_ROOT": str(reports_root),
                "SECOPS_HOST": api_host,
                "SECOPS_PORT": api_port,
                "SECOPS_UI_HOST": ui_host,
                "SECOPS_UI_PORT": ui_port,
                "SECOPS_DATABASE_URL": database_url,
                "VANTIX_SKILLS_ROOT": str(self.repo_root / "agent_skills"),
                "SECOPS_API_TOKEN": self.env_updates.get("SECOPS_API_TOKEN") or secrets.token_urlsafe(24),
                "SECOPS_CODEX_BIN": self.env_updates.get("SECOPS_CODEX_BIN") or "codex",
                "SECOPS_ENABLE_SCRIPT_EXECUTION": "true",
                "SECOPS_ENABLE_WRITE_EXECUTION": "true",
            }
        )

    def bootstrap_database(self) -> None:
        code = (
            "from pathlib import Path;"
            "from secops.config import settings;"
            "from secops.db import Base, engine;"
            "Path(settings.runtime_root).mkdir(parents=True, exist_ok=True);"
            "Path(settings.reports_root).mkdir(parents=True, exist_ok=True);"
            "Base.metadata.create_all(bind=engine);"
            "print('ok')"
        )
        proc = self._repo_python(code)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "Database bootstrap failed").strip())

    def configure_provider_flow(self) -> dict[str, Any]:
        codex_ok = self.ensure_codex_cli()
        codex_ok = self.codex_available()
        codex_logged_in = False
        if codex_ok and self.confirm("Authenticate Codex CLI now with device auth", default=True):
            codex_logged_in = self.codex_device_login()
            if not codex_logged_in:
                print("    [WARN] Codex login did not complete. You can run 'codex --device-auth' later.")
        provider_added = False
        provider_runtime: dict[str, Any] = {"provider_type": "", "runtime_installed": True}
        while True:
            if codex_ok:
                add_provider = self.confirm("Configure an optional provider record now", default=False)
            else:
                print("[!] Codex CLI not detected. Configure at least one provider to complete setup.")
                add_provider = True
            if add_provider:
                provider_type = self.choose(
                    "Provider type",
                    ["openai", "anthropic", "gemini", "ollama", "bedrock", "deepseek", "glm", "kimi", "qwen", "openrouter", "custom"],
                    "openai",
                )
                name = self.prompt("Provider name", provider_type)
                base_url = self.prompt("Provider base URL", "")
                default_model = self.prompt("Provider default model", "")
                secret = self.prompt("Provider secret/API key", "")
                if secret and not self.env_updates.get("VANTIX_SECRET_KEY"):
                    self.env_updates["VANTIX_SECRET_KEY"] = secrets.token_urlsafe(32)
                payload = {
                    "name": name,
                    "provider_type": provider_type,
                    "base_url": base_url,
                    "default_model": default_model,
                    "enabled": True,
                    "secret": secret,
                    "metadata": {"installed_by": "vantix-installer"},
                }
                self.write_env()
                self.bootstrap_provider(payload)
                provider_runtime = self.bootstrap_provider_runtime(provider_type)
                if not provider_runtime.get("runtime_installed", True):
                    print(f"    [WARN] {provider_runtime.get('detail', 'provider bootstrap incomplete')}")
                    hint = str(provider_runtime.get("hint", "")).strip()
                    if hint:
                        print(f"    [HINT] {hint}")
                provider_added = True
            provider_count = self.provider_count()
            if codex_ok or provider_count > 0 or provider_added:
                self.env_updates["SECOPS_ENABLE_CODEX_EXECUTION"] = "true" if codex_ok else "false"
                return {
                    "codex_available": codex_ok,
                    "codex_logged_in": codex_logged_in,
                    "provider_count": provider_count,
                    "provider_runtime": provider_runtime,
                }
            if not self.confirm("No runtime is configured. Retry provider setup", default=True):
                raise RuntimeError("At least one runtime must be configured before setup can complete")

    def _available_mongo_package(self) -> str:
        for package in ["mongodb", "mongodb-server", "mongodb-org"]:
            proc = self.run(["bash", "-lc", f"apt-cache show {package} >/dev/null 2>&1"])
            if proc.returncode == 0:
                return package
        return ""

    def cve_api_ready(self, url: str) -> bool:
        code = (
            "import sys, urllib.error, urllib.request;"
            "url=sys.argv[1].rstrip('/') + '/api/browse';"
            "\ntry:\n"
            "    with urllib.request.urlopen(url, timeout=3) as resp:\n"
            "        print(resp.status)\n"
            "except Exception:\n"
            "    print(0)\n"
        )
        proc = self.run([str(self.venv_python), "-c", code, url])
        return (proc.stdout or "").strip() == "200"

    def configure_cve(self) -> dict[str, Any]:
        deploy = self.confirm("Use local CVE search and MCP", default=True)
        refresh = self.choose("CVE refresh cadence", ["manual", "daily", "weekly"], "weekly")
        url = self.env_updates.get("SECOPS_CVE_SEARCH_URL", "http://127.0.0.1:5000")
        result = {"selected": deploy, "deployed": False, "refresh_cadence": refresh, "degraded": False, "url": url, "existing": False}
        if not deploy:
            self.env_updates["SECOPS_ENABLE_CVE_MCP"] = "false"
            self._configure_cve_refresh(refresh="manual")
            return result
        if self.cve_api_ready(url):
            print(f"    Existing CVE API is reachable: {url}")
            result.update({"deployed": True, "existing": True})
            self.env_updates["SECOPS_CVE_SEARCH_URL"] = url
            self.env_updates["SECOPS_ENABLE_CVE_MCP"] = "true"
            self.env_updates["SECOPS_CVE_MCP_REQUIRE_TOKEN"] = "true"
            self._configure_cve_refresh(refresh)
            return result
        packages = ["redis-server"]
        mongo_pkg = self._available_mongo_package()
        if mongo_pkg:
            packages.append(mongo_pkg)
        else:
            if not self.confirm("MongoDB package was not found via apt-cache. Continue in degraded CVE mode", default=False):
                raise RuntimeError("Local CVE deployment blocked: MongoDB package unavailable")
            result["degraded"] = True
        self.ensure_system_packages(packages)
        cve_root = self.repo_root / "tools" / "cve-search"
        proc = self.run_visible(["python3", "-m", "venv", str(cve_root / ".venv")], cwd=cve_root, label="Create cve-search virtual environment")
        if proc.returncode != 0 and not (cve_root / ".venv" / "bin" / "python").exists():
            raise RuntimeError("Failed to create cve-search virtual environment")
        pip = [str(cve_root / ".venv" / "bin" / "python"), "-m", "pip"]
        for command in ([*pip, "install", "--upgrade", "pip"], [*pip, "install", "-r", "requirements.txt"]):
            proc = self.run_visible(command, cwd=cve_root, label=" ".join(command[3:]))
            if proc.returncode != 0:
                if not self.confirm("cve-search dependency install failed. Continue in degraded mode", default=False):
                    raise RuntimeError("Local CVE dependency install failed")
                result["degraded"] = True
                break
        if not result["degraded"]:
            proc = self.run_visible(["bash", str(self.repo_root / "scripts" / "secops-cve-search.sh"), "start"], label="Start local CVE search")
            if proc.returncode != 0:
                raise RuntimeError("Failed to start local CVE search")
            result["deployed"] = self.cve_api_ready(url)
            if not result["deployed"]:
                print("    [WARN] CVE start command completed, but the API probe is not ready yet.")
                result["degraded"] = True
        self.env_updates["SECOPS_CVE_SEARCH_URL"] = url
        self.env_updates["SECOPS_ENABLE_CVE_MCP"] = "true"
        self.env_updates["SECOPS_CVE_MCP_REQUIRE_TOKEN"] = "true"
        self._configure_cve_refresh(refresh)
        return result

    def _configure_cve_refresh(self, refresh: str) -> None:
        marker_begin = "# BEGIN VANTIX_CVE_REFRESH"
        marker_end = "# END VANTIX_CVE_REFRESH"
        if refresh == "manual":
            proc = self.run(["bash", "-lc", "crontab -l 2>/dev/null || true"])
            current = (proc.stdout or "").splitlines()
            new_lines: list[str] = []
            skip = False
            for line in current:
                if line.strip() == marker_begin:
                    skip = True
                    continue
                if line.strip() == marker_end:
                    skip = False
                    continue
                if not skip:
                    new_lines.append(line)
            payload = "\n".join(new_lines).strip()
            if payload:
                self.run(["bash", "-lc", f"printf %s {json.dumps(payload + chr(10))} | crontab -"])
            return
        schedule = "0 3 * * *" if refresh == "daily" else "0 3 * * 0"
        command = f"{schedule} bash '{self.repo_root}/scripts/update-cve-intel-stack.sh' >/dev/null 2>&1"
        proc = self.run(["bash", "-lc", "crontab -l 2>/dev/null || true"])
        current = (proc.stdout or "").splitlines()
        new_lines: list[str] = []
        skip = False
        for line in current:
            if line.strip() == marker_begin:
                skip = True
                continue
            if line.strip() == marker_end:
                skip = False
                continue
            if not skip:
                new_lines.append(line)
        new_lines.extend([marker_begin, command, marker_end])
        payload = "\n".join(line for line in new_lines if line is not None).strip() + "\n"
        self.run(["bash", "-lc", f"printf %s {json.dumps(payload)} | crontab -"])

    def configure_tools(self) -> dict[str, Any]:
        suite = self.choose("Host tool suite", ["skip", "minimal", "common", "full"], "common")
        if suite == "skip":
            return {"suite": "skip", "results": []}
        suite_tools = self.tool_service.suites().get(suite, {}).get("tools", [])
        print(f"    Installing tool suite: {suite} ({len(suite_tools)} tools)")
        results = self.tool_service.install_tools(suite_tools, apply=True)
        ok_count = sum(1 for row in results if row.get("ok"))
        for row in results:
            status = row.get("status") or row.get("reason") or ("ok" if row.get("ok") else "failed")
            print(f"    - {row.get('tool_id')}: {status}")
        print(f"    Tool suite result: {ok_count}/{len(results)} ready")
        return {"suite": suite, "results": results}

    def _user_systemd_dir(self) -> Path:
        config_home = Path(os.getenv("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        return config_home / "systemd" / "user"

    def install_user_systemd_units(self) -> dict[str, Any]:
        unit_dir = self._user_systemd_dir()
        unit_dir.mkdir(parents=True, exist_ok=True)
        units = {
            SERVICE_NAMES["api"]: render_user_systemd_unit(
                description="Vantix API",
                repo_root=self.repo_root,
                script_path=self.repo_root / "scripts" / "secops-api.sh",
            ),
            SERVICE_NAMES["ui"]: render_user_systemd_unit(
                description="Vantix UI",
                repo_root=self.repo_root,
                script_path=self.repo_root / "scripts" / "secops-ui.sh",
            ),
        }
        written: list[str] = []
        for name, content in units.items():
            path = unit_dir / name
            path.write_text(content, encoding="utf-8")
            written.append(str(path))
            print(f"    Wrote {path}")
        return {"unit_dir": str(unit_dir), "unit_files": written, "unit_names": list(units)}

    def configure_user_systemd(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "mode": "manual",
            "installed": False,
            "enabled": False,
            "started": False,
            "linger": False,
            "units": list(SERVICE_NAMES.values()),
        }
        if not self.confirm("Install Vantix API/UI as user systemd services", default=True):
            print("    Service mode: manual scripts")
            return result
        if not shutil.which("systemctl"):
            raise RuntimeError("systemctl was not found; cannot install user systemd services")
        unit_info = self.install_user_systemd_units()
        result.update({"mode": "user-systemd", "installed": True, **unit_info})
        proc = self.run_visible(["systemctl", "--user", "daemon-reload"], label="Reload user systemd manager")
        if proc.returncode != 0:
            raise RuntimeError("Failed to reload the user systemd manager")
        if self.confirm("Enable and start Vantix services now", default=True):
            proc = self.run_visible(["systemctl", "--user", "enable", "--now", *SERVICE_NAMES.values()], label="Enable and start Vantix services")
            if proc.returncode != 0:
                raise RuntimeError("Failed to enable/start Vantix user services")
            result.update({"enabled": True, "started": True})
        if self.confirm("Enable boot startup without an active login using loginctl linger", default=False):
            user = os.getenv("USER") or getpass.getuser()
            proc = self.run_visible(["loginctl", "enable-linger", user], label=f"Enable lingering for {user}")
            if proc.returncode == 0:
                result["linger"] = True
            else:
                print("    [WARN] Linger setup failed. Services still work while the user systemd manager is running.")
                result["linger_error"] = proc.stdout
        status = self.run(["systemctl", "--user", "is-active", *SERVICE_NAMES.values()])
        result["active"] = (status.stdout or "").splitlines()
        return result

    def write_env(self) -> None:
        write_env_file(self.env_path, self.env_updates, template_path=self.env_example)

    def verify(self) -> dict[str, Any]:
        tool_statuses = self.tool_service.list_tools()
        provider_count = self.provider_count()
        codex_ok = self.codex_available()
        api_ready = self.venv_python.exists()
        frontend_dist = (self.repo_root / "frontend" / "dist").exists()
        cve_status = self.run(["bash", str(self.repo_root / "scripts" / "secops-cve-search.sh"), "status"])
        cve_ready = cve_status.returncode == 0 and "HTTP:200" in (cve_status.stdout or "")
        ready = api_ready and (codex_ok or provider_count > 0)
        return {
            "ready": ready,
            "api_ready": api_ready,
            "frontend_built": frontend_dist,
            "codex_available": codex_ok,
            "provider_count": provider_count,
            "cve_ready": cve_ready,
            "installed_tools": sum(1 for row in tool_statuses if row.get("installed")),
            "tool_count": len(tool_statuses),
        }

    def interface_urls(self) -> dict[str, str]:
        api_host = self.env_updates.get("SECOPS_HOST", "127.0.0.1")
        api_port = self.env_updates.get("SECOPS_PORT", "8787")
        ui_host = self.env_updates.get("SECOPS_UI_HOST", "127.0.0.1")
        ui_port = self.env_updates.get("SECOPS_UI_PORT", "4173")
        return {
            "api_base": f"http://{api_host}:{api_port}",
            "ui_root": f"http://{ui_host}:{ui_port}",
            "ui_app": f"http://{api_host}:{api_port}/ui",
        }

    def run_wizard(self) -> dict[str, Any]:
        self.print_intro()
        self.section("Host preflight", "Checking the operating system and installer prerequisites.")
        os_info = self.os_info()
        if not os_info["debian_family"]:
            raise RuntimeError("Vantix installer currently supports Debian-family hosts only")
        print(f"    OS: {os_info['name']}")
        self.section("Runtime configuration", "Choosing user-owned runtime paths and writing .env.")
        self.configure_runtime()
        self.write_env()
        self.section("Backend environment", "Installing Python dependencies and the editable backend package.")
        self.ensure_backend()
        self.bootstrap_database()
        self.section("Browser runtime", "Installing Playwright and Chromium for browser-native assessment.")
        browser_runtime = self.ensure_browser_runtime()
        self.section("Web UI", "Installing frontend dependencies and optionally building the static UI.")
        frontend = self.ensure_frontend(build=self.confirm("Build the static Web UI now", default=True))
        self.section("Runtime provider", "Checking Codex and optional model provider configuration.")
        runtime = self.configure_provider_flow()
        self.section("CVE intel", "Configuring optional local CVE search and MCP support.")
        cve = self.configure_cve()
        self.section("Host tool suite", "Installing selected operator tools from the allowlisted registry.")
        tools = self.configure_tools()
        self.write_env()
        self.section("Verification", "Checking backend, frontend, runtime, CVE, and tool readiness.")
        verify = self.verify()
        print(f"    Ready: {bool(verify['ready'])}")
        print(f"    Frontend built: {bool(verify['frontend_built'])}")
        print(f"    Tools installed: {verify['installed_tools']}/{verify['tool_count']}")
        self.section("Service startup", "Optionally installing user systemd services for API and UI.")
        services = self.configure_user_systemd()
        state = {
            "ready": bool(verify["ready"]),
            "repo_root": str(self.repo_root),
            "runtime_root": str(self.runtime_root),
            "updated_at": "",
            "os": os_info,
            "frontend": frontend,
            "browser_runtime": browser_runtime,
            "runtime": runtime,
            "cve": cve,
            "tools": tools,
            "verify": verify,
            "services": services,
            "interfaces": self.interface_urls(),
        }
        self.state.write(state)
        return state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Interactive Vantix installer")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args(argv)
    wizard = Wizard(Path(args.repo_root))
    try:
        state = wizard.run_wizard()
    except KeyboardInterrupt:
        print("\n[!] Installation aborted by operator.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Installation failed: {exc}", file=sys.stderr)
        return 1
    print("\n[+] Installation complete")
    print(f"    ready={state.get('ready')}")
    print(f"    runtime_root={state.get('runtime_root')}")
    interfaces = state.get("interfaces") or {}
    print(f"    api_url={interfaces.get('api_base', 'http://127.0.0.1:8787')}")
    print(f"    ui_url={interfaces.get('ui_root', 'http://127.0.0.1:4173')}")
    print(f"    bundled_ui_url={interfaces.get('ui_app', 'http://127.0.0.1:8787/ui')}")
    services = state.get("services") or {}
    if services.get("mode") == "user-systemd" and services.get("installed"):
        print("    service_mode=user-systemd")
        print("    status:  systemctl --user status vantix-api.service vantix-ui.service")
        print("    logs:    journalctl --user -u vantix-api.service -u vantix-ui.service -f")
        if not services.get("started"):
            print("    start:   systemctl --user enable --now vantix-api.service vantix-ui.service")
    else:
        print("    service_mode=manual")
        print("    start:  bash scripts/vantixctl.sh start")
        print("    status: bash scripts/vantixctl.sh status")
    print("    doctor: bash scripts/doctor.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
