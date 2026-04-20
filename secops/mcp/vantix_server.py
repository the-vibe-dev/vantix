from __future__ import annotations

import argparse
from typing import Any

from sqlalchemy.orm import Session

from secops.config import settings
from secops.db import SessionLocal
from secops.models import WorkspaceRun
from secops.services.execution import execution_manager
from secops.services.source_intake import SourceIntakeService


def _run_or_error(db: Session, run_id: str) -> WorkspaceRun:
    run = db.get(WorkspaceRun, run_id)
    if run is None:
        raise ValueError(f"Run not found: {run_id}")
    return run


def create_vantix_mcp():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Install MCP dependencies first: pip install -e .") from exc

    mcp = FastMCP(
        "Vantix Source Ops",
        stateless_http=True,
        json_response=True,
    )

    @mcp.tool()
    def attach_run_source(run_id: str, source_input: dict[str, Any]) -> dict[str, Any]:
        """Attach source input metadata to a run for white-box phases."""
        with SessionLocal() as db:
            run = _run_or_error(db, run_id)
            cfg = dict(run.config_json or {})
            cfg["source_input"] = source_input
            run.config_json = cfg
            db.commit()
            return {"run_id": run_id, "attached": True, "source_input": source_input}

    @mcp.tool()
    def get_run_source_status(run_id: str) -> dict[str, Any]:
        """Return run source metadata and resolved status."""
        with SessionLocal() as db:
            run = _run_or_error(db, run_id)
            cfg = dict(run.config_json or {})
            return {
                "run_id": run_id,
                "source_input": cfg.get("source_input", {}),
                "source_context": cfg.get("source_context", {}),
            }

    @mcp.tool()
    def run_source_analysis(run_id: str) -> dict[str, Any]:
        """Queue run execution so source phases run through workflow."""
        return {"run_id": run_id, "message": execution_manager.start(run_id)}

    @mcp.tool()
    def register_staged_upload(name: str, staged_upload_id: str) -> dict[str, Any]:
        """Helper metadata tool for upload references used by clients."""
        return {"name": name, "staged_upload_id": staged_upload_id, "upload_root": str(SourceIntakeService().upload_root)}

    return mcp


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Vantix MCP server")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8789)
    args = parser.parse_args()
    mcp = create_vantix_mcp()
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="streamable-http")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

