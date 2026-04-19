from __future__ import annotations

from pathlib import Path

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


@router.get("/status", response_model=SystemStatusRead)
def system_status(db: Session = Depends(get_db)) -> dict:
    runner = CodexRunner(workspace_dir=settings.runtime_root / "status" / "codex")
    codex_path = runner.resolve_binary()
    runtime_ok = _writable(settings.runtime_root)
    artifacts_root = Path(settings.reports_root)
    artifacts_ok = _writable(artifacts_root)
    memory = MemoryWriteService().health(stale_minutes=120)
    provider_count = db.query(ProviderConfig).count()
    installer_state = InstallerStateService().read()
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
        },
        "tooling": {
            "count": len(tool_statuses),
            "installed": installed_tools,
            "missing": len(tool_statuses) - installed_tools,
            "debian_family": tool_service.os_info().get("debian_family", False),
            "kali": tool_service.os_info().get("kali", False),
        },
        "warnings": warnings,
    }


@router.get("/install-status", response_model=InstallerStateRead)
def install_status() -> dict:
    state = InstallerStateService().read()
    return {"ready": bool(state.get("ready")), "updated_at": state.get("updated_at", ""), "state": state}
