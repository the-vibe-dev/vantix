from __future__ import annotations

import subprocess
from pathlib import Path
from dataclasses import asdict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secops.config import settings
from secops.db import get_db
from secops.models import ProviderConfig
from secops.schemas import InstallerStateRead, SystemStatusRead
from secops.security import require_api_token
from secops.services.codex_runner import CodexRunner
from secops.services.installer_state import InstallerStateService
from secops.services.memory_writer import MemoryWriteService
from secops.services.tools import ToolService
from secops.services.worker_runtime import worker_runtime

router = APIRouter(prefix="/api/v1/system", tags=["system"], dependencies=[Depends(require_api_token)])


def _writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _git_status(repo_root: Path) -> dict:
    def run(*args: str) -> str:
        proc = subprocess.run(["git", *args], cwd=repo_root, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return ""
        return (proc.stdout or "").strip()

    if not (repo_root / ".git").exists():
        return {"available": False}
    current = run("rev-parse", "HEAD")
    target = run("rev-parse", "origin/main")
    ahead = run("rev-list", "--count", "HEAD..origin/main") if target else "0"
    behind = run("rev-list", "--count", "origin/main..HEAD") if target else "0"
    dirty = run("status", "--porcelain", "--untracked-files=all")
    return {
        "available": True,
        "branch": run("branch", "--show-current"),
        "remote": run("remote", "get-url", "origin"),
        "current_commit": current,
        "target_commit": target,
        "updates_available": bool(target and current != target and ahead not in {"", "0"}),
        "ahead_count": int(ahead or 0),
        "behind_count": int(behind or 0),
        "clean": not bool(dirty),
    }


@router.get("/status", response_model=SystemStatusRead)
def system_status(db: Session = Depends(get_db)) -> dict:
    runner = CodexRunner(workspace_dir=settings.runtime_root / "status" / "codex")
    codex_path = runner.resolve_binary()
    runtime_ok = _writable(settings.runtime_root)
    artifacts_root = Path(settings.reports_root)
    artifacts_ok = _writable(artifacts_root)
    memory = MemoryWriteService().health(stale_minutes=120)
    provider_count = db.query(ProviderConfig).count()
    installer_service = InstallerStateService()
    installer_state = installer_service.read()
    git = _git_status(settings.repo_root)
    tool_service = ToolService()
    tool_statuses = tool_service.list_tools()
    installed_tools = sum(1 for row in tool_statuses if row.get("installed"))
    warnings: list[str] = []
    if not codex_path:
        warnings.append("Codex binary is not available on PATH or SECOPS_CODEX_BIN")
    if not settings.enable_codex_execution:
        warnings.append("Codex execution is disabled")
    if not runtime_ok:
        warnings.append("Runtime root is not writable")
    return {
        "product": "Vantix",
        "version": "0.1.0",
        "default_runtime": "codex",
        "codex": {"configured_bin": settings.codex_bin, "available": bool(codex_path), "path": codex_path or ""},
        "execution": {
            "codex_enabled": settings.enable_codex_execution,
            "script_enabled": settings.enable_script_execution,
            "write_enabled": settings.enable_write_execution,
        },
        "runtime": {"path": str(settings.runtime_root), "writable": runtime_ok},
        "artifacts": {"path": str(artifacts_root), "writable": artifacts_ok},
        "memory": memory,
        "cve_mcp": {"enabled": settings.enable_cve_mcp, "path": settings.cve_mcp_path},
        "providers": {"count": provider_count, "default_runtime": "codex"},
        "installer": {
            "ready": bool(installer_state.get("ready")),
            "updated_at": installer_state.get("updated_at", ""),
            "selected_suite": (installer_state.get("tools") or {}).get("suite", ""),
            "cve_refresh": (installer_state.get("cve") or {}).get("refresh_cadence", ""),
            "git": git,
            "last_update": installer_state.get("last_update", {}),
        },
        "tooling": {
            "count": len(tool_statuses),
            "installed": installed_tools,
            "missing": len(tool_statuses) - installed_tools,
            "debian_family": tool_service.os_info().get("debian_family", False),
            "kali": tool_service.os_info().get("kali", False),
        },
        "worker": asdict(worker_runtime.snapshot()),
        "warnings": warnings,
    }


@router.get("/install-status", response_model=InstallerStateRead)
def install_status() -> dict:
    service = InstallerStateService()
    state = service.read()
    state.setdefault("update_history", service.update_history(limit=20))
    state.setdefault("git", _git_status(settings.repo_root))
    return {"ready": bool(state.get("ready")), "updated_at": state.get("updated_at", ""), "state": state}
