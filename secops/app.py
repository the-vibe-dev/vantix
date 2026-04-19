from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from secops.config import settings
from secops.db import Base, engine
from secops.routers import approvals, benchmarks, chat, cve, engagements, health, memory, modes, providers, runs, skills, system, tasks, tools


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Vantix",
        version="0.1.0",
        description="Codex-native Vantix backend for authorized CTF, KoTH, pentest, and bug bounty workflows.",
        lifespan=lifespan,
    )

    app.include_router(health.router)
    app.include_router(system.router)
    app.include_router(chat.router)
    app.include_router(modes.router)
    app.include_router(engagements.router)
    app.include_router(runs.router)
    app.include_router(skills.router)
    app.include_router(tasks.router)
    app.include_router(memory.router)
    app.include_router(cve.router)
    app.include_router(approvals.router)
    app.include_router(benchmarks.router)
    app.include_router(providers.router)
    app.include_router(tools.router)

    if settings.enable_cve_mcp:
        from secops.mcp.cve_server import create_cve_mcp
        from secops.mcp.security import MCPAuthAndOriginMiddleware

        mcp_app = create_cve_mcp().streamable_http_app()
        app.mount(settings.cve_mcp_path, MCPAuthAndOriginMiddleware(mcp_app), name="cve-mcp")

    dist_dir = Path(settings.frontend_root) / "dist"
    if dist_dir.exists():
        app.mount("/ui", StaticFiles(directory=dist_dir, html=True), name="ui")
    return app


app = create_app()
