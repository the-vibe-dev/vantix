from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from secops.services.installer_state import InstallerStateService
from secops.services.tools import ToolService


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

    def os_info(self) -> dict[str, Any]:
        return self.tool_service.os_info()

    def ensure_system_packages(self, packages: list[str]) -> None:
        packages = [pkg for pkg in packages if pkg]
        if not packages:
            return
        missing = []
        for pkg in packages:
            proc = self.run(["bash", "-lc", f"dpkg -s {pkg} >/dev/null 2>&1"])
            if proc.returncode != 0:
                missing.append(pkg)
        if not missing:
            return
        print(f"[*] Installing system packages: {' '.join(missing)}")
        self.run(["sudo", "apt-get", "update"])
        proc = self.run(["sudo", "apt-get", "install", "-y", *missing])
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to install packages: {' '.join(missing)}")

    def ensure_backend(self) -> None:
        self.ensure_system_packages(["python3", "python3-venv", "python3-pip", "git"])
        if not self.venv_python.exists():
            proc = self.run(["python3", "-m", "venv", str(self.repo_root / ".venv")])
            if proc.returncode != 0:
                raise RuntimeError("Failed to create Python virtual environment")
        pip = [str(self.venv_python), "-m", "pip"]
        for command in ([*pip, "install", "--upgrade", "pip"], [*pip, "install", "-e", ".[dev]"]):
            proc = self.run(command)
            if proc.returncode != 0:
                raise RuntimeError(f"Failed backend bootstrap: {' '.join(command)}")

    def ensure_corepack(self) -> None:
        if shutil.which("corepack"):
            return
        if not shutil.which("npm"):
            raise RuntimeError("npm is required to install corepack")
        proc = self.run(["sudo", "npm", "install", "-g", "corepack"])
        if proc.returncode != 0:
            raise RuntimeError("Failed to install corepack with npm")

    def ensure_frontend(self, build: bool = True) -> dict[str, Any]:
        self.ensure_system_packages(["nodejs", "npm"])
        self.ensure_corepack()
        frontend_root = self.repo_root / "frontend"
        proc = self.run(["corepack", "pnpm", "install"], cwd=frontend_root)
        if proc.returncode != 0:
            raise RuntimeError("Failed frontend dependency install")
        built = False
        if build:
            proc = self.run(["corepack", "pnpm", "build"], cwd=frontend_root)
            if proc.returncode != 0:
                raise RuntimeError("Failed frontend build")
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

    def configure_runtime(self) -> None:
        default_runtime = str(self.runtime_root)
        runtime = self.prompt("Runtime root", default_runtime)
        self.runtime_root = Path(runtime).expanduser().resolve()
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.state = InstallerStateService(self.runtime_root)
        self.tool_service = ToolService(self.repo_root, self.runtime_root)
        self.env_updates.update(
            {
                "SECOPS_REPO_ROOT": str(self.repo_root),
                "SECOPS_RUNTIME_ROOT": str(self.runtime_root),
                "SECOPS_REPORTS_ROOT": str(self.runtime_root / "reports"),
                "SECOPS_API_TOKEN": self.env_updates.get("SECOPS_API_TOKEN") or secrets.token_urlsafe(24),
                "SECOPS_CODEX_BIN": self.env_updates.get("SECOPS_CODEX_BIN") or "codex",
                "SECOPS_ENABLE_SCRIPT_EXECUTION": "true",
                "SECOPS_ENABLE_WRITE_EXECUTION": "true",
            }
        )

    def configure_provider_flow(self) -> dict[str, Any]:
        codex_ok = self.codex_available()
        provider_added = False
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
                provider_added = True
            provider_count = self.provider_count()
            if codex_ok or provider_count > 0 or provider_added:
                self.env_updates["SECOPS_ENABLE_CODEX_EXECUTION"] = "true" if codex_ok else "false"
                return {"codex_available": codex_ok, "provider_count": provider_count}
            if not self.confirm("No runtime is configured. Retry provider setup", default=True):
                raise RuntimeError("At least one runtime must be configured before setup can complete")

    def _available_mongo_package(self) -> str:
        for package in ["mongodb", "mongodb-server", "mongodb-org"]:
            proc = self.run(["bash", "-lc", f"apt-cache show {package} >/dev/null 2>&1"])
            if proc.returncode == 0:
                return package
        return ""

    def configure_cve(self) -> dict[str, Any]:
        deploy = self.confirm("Deploy local CVE search and MCP", default=True)
        refresh = self.choose("CVE refresh cadence", ["manual", "daily", "weekly"], "weekly")
        result = {"selected": deploy, "deployed": False, "refresh_cadence": refresh, "degraded": False}
        if not deploy:
            self.env_updates["SECOPS_ENABLE_CVE_MCP"] = "false"
            self._configure_cve_refresh(refresh="manual")
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
        proc = self.run(["python3", "-m", "venv", str(cve_root / ".venv")], cwd=cve_root)
        if proc.returncode != 0 and not (cve_root / ".venv" / "bin" / "python").exists():
            raise RuntimeError("Failed to create cve-search virtual environment")
        pip = [str(cve_root / ".venv" / "bin" / "python"), "-m", "pip"]
        for command in ([*pip, "install", "--upgrade", "pip"], [*pip, "install", "-r", "requirements.txt"]):
            proc = self.run(command, cwd=cve_root)
            if proc.returncode != 0:
                if not self.confirm("cve-search dependency install failed. Continue in degraded mode", default=False):
                    raise RuntimeError("Local CVE dependency install failed")
                result["degraded"] = True
                break
        if not result["degraded"]:
            self.run(["bash", str(self.repo_root / "scripts" / "secops-cve-search.sh"), "start"])
            result["deployed"] = True
        self.env_updates["SECOPS_CVE_SEARCH_URL"] = "http://127.0.0.1:5000"
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
        print(f"[*] Installing tool suite: {suite} ({len(suite_tools)} tools)")
        results = self.tool_service.install_tools(suite_tools, apply=True)
        return {"suite": suite, "results": results}

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

    def run_wizard(self) -> dict[str, Any]:
        os_info = self.os_info()
        if not os_info["debian_family"]:
            raise RuntimeError("Vantix installer currently supports Debian-family hosts only")
        print(f"== Vantix Installer ==\nOS: {os_info['name']}")
        self.configure_runtime()
        self.write_env()
        self.ensure_backend()
        frontend = self.ensure_frontend(build=self.confirm("Build the static Web UI now", default=True))
        runtime = self.configure_provider_flow()
        cve = self.configure_cve()
        tools = self.configure_tools()
        self.write_env()
        verify = self.verify()
        state = {
            "ready": bool(verify["ready"]),
            "repo_root": str(self.repo_root),
            "runtime_root": str(self.runtime_root),
            "updated_at": "",
            "os": os_info,
            "frontend": frontend,
            "runtime": runtime,
            "cve": cve,
            "tools": tools,
            "verify": verify,
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
    print("    start_api: bash scripts/secops-api.sh")
    print("    start_ui:  bash scripts/secops-ui.sh")
    print("    status:    bash scripts/doctor.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
