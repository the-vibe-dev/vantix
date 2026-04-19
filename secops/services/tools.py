from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from secops.config import settings
from secops.services.installer_state import InstallerStateService


@dataclass(frozen=True)
class ToolDefinition:
    id: str
    name: str
    binaries: list[str]
    suites: list[str]
    allow_auto_install: bool
    install: dict[str, Any]


class ToolRegistry:
    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = (repo_root or settings.repo_root).resolve()
        self.registry_path = self.repo_root / "agent_ops" / "config" / "tool_registry.yaml"
        self.suites_path = self.repo_root / "agent_ops" / "config" / "tool_suites.yaml"
        self._tools = self._load_tools()
        self._suites = self._load_suites()

    def _load_tools(self) -> dict[str, ToolDefinition]:
        if not self.registry_path.exists():
            return {}
        raw = yaml.safe_load(self.registry_path.read_text(encoding="utf-8")) or {}
        out: dict[str, ToolDefinition] = {}
        for item in raw.get("tools", []):
            tool = ToolDefinition(
                id=str(item["id"]),
                name=str(item.get("name") or item["id"]),
                binaries=[str(part) for part in item.get("binaries", [])],
                suites=[str(part) for part in item.get("suites", [])],
                allow_auto_install=bool(item.get("allow_auto_install", False)),
                install=dict(item.get("install") or {}),
            )
            out[tool.id] = tool
        return out

    def _load_suites(self) -> dict[str, dict[str, Any]]:
        if not self.suites_path.exists():
            return {}
        raw = yaml.safe_load(self.suites_path.read_text(encoding="utf-8")) or {}
        return {str(name): dict(config or {}) for name, config in (raw.get("suites") or {}).items()}

    def all(self) -> list[ToolDefinition]:
        return [self._tools[key] for key in sorted(self._tools)]

    def get(self, tool_id: str) -> ToolDefinition | None:
        return self._tools.get(tool_id)

    def suites(self) -> dict[str, dict[str, Any]]:
        return dict(self._suites)

    def resolve_suite(self, suite: str) -> list[ToolDefinition]:
        config = self._suites.get(suite, {})
        return [self._tools[tool_id] for tool_id in config.get("tools", []) if tool_id in self._tools]


class ToolService:
    def __init__(self, repo_root: Path | None = None, runtime_root: Path | None = None) -> None:
        self.repo_root = (repo_root or settings.repo_root).resolve()
        self.runtime_root = (runtime_root or settings.runtime_root).resolve()
        self.registry = ToolRegistry(self.repo_root)
        self.state = InstallerStateService(self.runtime_root)

    def os_info(self) -> dict[str, Any]:
        info: dict[str, str] = {}
        os_release = Path("/etc/os-release")
        if os_release.exists():
            for raw in os_release.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "=" not in raw:
                    continue
                key, value = raw.split("=", 1)
                info[key] = value.strip().strip('"')
        distro_id = info.get("ID", "").lower()
        like = [part.strip().lower() for part in info.get("ID_LIKE", "").split() if part.strip()]
        families = {distro_id, *like}
        return {
            "id": distro_id,
            "name": info.get("PRETTY_NAME") or info.get("NAME", ""),
            "like": like,
            "family": sorted(families),
            "debian_family": any(part in {"debian", "ubuntu", "kali"} for part in families),
            "kali": distro_id == "kali",
        }

    def locate_binary(self, name: str) -> str | None:
        candidates = [
            shutil.which(name),
            str(Path.home() / "go" / "bin" / name),
            str(Path.home() / ".local" / "bin" / name),
        ]
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return candidate
        return None

    def _binary_version(self, path: str) -> str:
        for args in ([path, "--version"], [path, "version"], [path, "-V"]):
            try:
                proc = subprocess.run(args, capture_output=True, text=True, check=False, timeout=10)
            except OSError:
                continue
            output = (proc.stdout or proc.stderr or "").strip().splitlines()
            if output:
                return output[0][:240]
        return ""

    def _last_history(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for row in self.state.tool_history(limit=500):
            tool_id = str(row.get("tool_id", ""))
            if tool_id:
                out[tool_id] = row
        return out

    def tool_status(self, tool: ToolDefinition) -> dict[str, Any]:
        found_path = None
        found_binary = ""
        for binary in tool.binaries:
            found_path = self.locate_binary(binary)
            if found_path:
                found_binary = binary
                break
        os_info = self.os_info()
        install = tool.install or {}
        method = str(install.get("method", ""))
        installable = os_info["debian_family"] and tool.allow_auto_install and method in {"apt", "go", "pipx"}
        last = self._last_history().get(tool.id, {})
        return {
            "id": tool.id,
            "name": tool.name,
            "binaries": tool.binaries,
            "suites": tool.suites,
            "method": method,
            "installed": bool(found_path),
            "binary": found_binary,
            "path": found_path or "",
            "version": self._binary_version(found_path) if found_path else "",
            "installable": installable,
            "allow_auto_install": tool.allow_auto_install,
            "last_result": last,
        }

    def list_tools(self, suite: str | None = None) -> list[dict[str, Any]]:
        tools = self.registry.resolve_suite(suite) if suite else self.registry.all()
        return [self.tool_status(tool) for tool in tools]

    def suites(self) -> dict[str, Any]:
        return self.registry.suites()

    def install_history(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.state.tool_history(limit=limit)

    def _run(self, command: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, check=False, env=env)

    def _apt_available_package(self, packages: list[str]) -> list[str]:
        available: list[str] = []
        for package in packages:
            proc = self._run(["bash", "-lc", f"apt-cache show {package} >/dev/null 2>&1"])
            if proc.returncode == 0:
                available.append(package)
        return available

    def _apt_sources_configured(self) -> bool:
        paths = [Path("/etc/apt/sources.list"), *Path("/etc/apt/sources.list.d").glob("*.list"), *Path("/etc/apt/sources.list.d").glob("*.sources")]
        for path in paths:
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
            "| sudo tee /etc/apt/sources.list && sudo apt-get update"
        )

    def install_tools(self, tool_ids: list[str], *, apply: bool = True) -> list[dict[str, Any]]:
        os_info = self.os_info()
        if not os_info["debian_family"]:
            raise RuntimeError("Tool installation is supported only on Debian-family systems in this version")
        results: list[dict[str, Any]] = []
        apt_updated = False
        for tool_id in tool_ids:
            tool = self.registry.get(tool_id)
            if tool is None:
                results.append({"tool_id": tool_id, "ok": False, "reason": "unknown-tool"})
                continue
            status = self.tool_status(tool)
            if status["installed"]:
                results.append({"tool_id": tool_id, "ok": True, "status": "already-installed", "path": status["path"], "version": status["version"]})
                continue
            install = tool.install or {}
            method = str(install.get("method", ""))
            commands: list[list[str]] = []
            env = os.environ.copy()
            ok = False
            reason = ""
            outputs: list[str] = []
            if method == "apt":
                if not self._apt_sources_configured():
                    reason = "apt-sources-missing"
                    payload = {
                        "tool_id": tool.id,
                        "method": method,
                        "ok": False,
                        "reason": reason,
                        "commands": [],
                        "output_tail": self._apt_recovery_hint(),
                    }
                    self.state.append_tool_history(payload)
                    results.append(payload)
                    continue
                packages = self._apt_available_package([str(item) for item in install.get("packages", [])])
                if not packages:
                    reason = "no-apt-package"
                else:
                    if apply and not apt_updated:
                        proc = self._run(["sudo", "apt-get", "update"])
                        outputs.append((proc.stdout or "") + (proc.stderr or ""))
                        apt_updated = proc.returncode == 0
                        if not apt_updated:
                            reason = "apt-update-failed"
                    commands.append(["sudo", "apt-get", "install", "-y", *packages])
            elif method == "go":
                prereqs = self._apt_available_package([str(item) for item in install.get("prereq_packages", [])])
                if prereqs and apply and not self.locate_binary("go"):
                    if not self._apt_sources_configured():
                        reason = "apt-sources-missing"
                        payload = {
                            "tool_id": tool.id,
                            "method": method,
                            "ok": False,
                            "reason": reason,
                            "commands": [],
                            "output_tail": self._apt_recovery_hint(),
                        }
                        self.state.append_tool_history(payload)
                        results.append(payload)
                        continue
                    if not apt_updated:
                        proc = self._run(["sudo", "apt-get", "update"])
                        outputs.append((proc.stdout or "") + (proc.stderr or ""))
                        apt_updated = proc.returncode == 0
                        if not apt_updated:
                            reason = "apt-update-failed"
                    commands.append(["sudo", "apt-get", "install", "-y", *prereqs])
                pkg = str(install.get("package", ""))
                env["GOPATH"] = str(Path.home() / "go")
                env["PATH"] = f"{env.get('PATH', '')}:{Path.home() / 'go' / 'bin'}"
                commands.append(["go", "install", pkg])
            elif method == "pipx":
                prereqs = self._apt_available_package([str(item) for item in install.get("prereq_packages", ["pipx"])])
                if prereqs and apply and not self.locate_binary("pipx"):
                    if not self._apt_sources_configured():
                        reason = "apt-sources-missing"
                        payload = {
                            "tool_id": tool.id,
                            "method": method,
                            "ok": False,
                            "reason": reason,
                            "commands": [],
                            "output_tail": self._apt_recovery_hint(),
                        }
                        self.state.append_tool_history(payload)
                        results.append(payload)
                        continue
                    if not apt_updated:
                        proc = self._run(["sudo", "apt-get", "update"])
                        outputs.append((proc.stdout or "") + (proc.stderr or ""))
                        apt_updated = proc.returncode == 0
                        if not apt_updated:
                            reason = "apt-update-failed"
                    commands.append(["sudo", "apt-get", "install", "-y", *prereqs])
                commands.append(["pipx", "install", str(install.get("package", ""))])
            else:
                reason = "unsupported-method"

            if reason:
                payload = {"tool_id": tool.id, "method": method, "ok": False, "reason": reason, "commands": commands}
                self.state.append_tool_history(payload)
                results.append(payload)
                continue

            if not apply:
                results.append({"tool_id": tool.id, "method": method, "ok": True, "status": "planned", "commands": commands})
                continue

            for command in commands:
                proc = self._run(command, env=env)
                outputs.append((proc.stdout or "") + (proc.stderr or ""))
                if proc.returncode != 0:
                    reason = f"command-failed:{command[0]}"
                    break

            fresh = self.tool_status(tool)
            ok = fresh["installed"] and not reason
            payload = {
                "tool_id": tool.id,
                "method": method,
                "ok": ok,
                "reason": reason,
                "commands": commands,
                "path": fresh.get("path", ""),
                "version": fresh.get("version", ""),
                "output_tail": "\n".join(outputs)[-4000:],
            }
            self.state.append_tool_history(payload)
            results.append(payload)
        return results
