from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from secops.config import settings
from secops.db import Base, engine
from secops.middleware import AuditMiddleware, RateLimitMiddleware, RequestIdMiddleware
from secops.routers import approvals, auth, benchmarks, chat, cve, engagements, health, memory, modes, providers, runs, skills, sources, system, tasks, tools


logger = logging.getLogger("secops")


def _check_startup_config() -> None:
    if not settings.api_token and not settings.dev_mode:
        sys.stderr.write(
            "FATAL: SECOPS_API_TOKEN is empty. Set it, or set SECOPS_DEV_MODE=1 for development.\n"
        )
        raise SystemExit(2)
    if any([settings.enable_write_execution, settings.enable_codex_execution, settings.enable_script_execution]):
        logger.warning(
            "Execution enabled: write=%s codex=%s script=%s",
            settings.enable_write_execution,
            settings.enable_codex_execution,
            settings.enable_script_execution,
        )


def _run_migrations_if_needed() -> None:
    """Postgres: run alembic upgrade head. SQLite: fall back to create_all (fast-path for dev/tests)."""
    dialect = engine.dialect.name
    if dialect == "sqlite":
        Base.metadata.create_all(bind=engine)
        return
    from alembic import command
    from alembic.config import Config as AlembicConfig
    cfg = AlembicConfig(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(cfg, "head")


def _bootstrap_admin_if_needed() -> None:
    try:
        from secops.db import SessionLocal
        from secops.services.auth_service import bootstrap_admin_if_needed
        with SessionLocal() as db:
            created = bootstrap_admin_if_needed(db)
            if created is not None:
                db.commit()
                logger.warning("bootstrap admin user created: %s", created.username)
    except Exception:  # noqa: BLE001
        logger.exception("admin bootstrap failed")


@asynccontextmanager
async def lifespan(_: FastAPI):
    _check_startup_config()
    _run_migrations_if_needed()
    _bootstrap_admin_if_needed()
    try:
        yield
    finally:
        try:
            from secops.services.worker_runtime import worker_runtime
            worker_runtime.stop()
        except Exception:  # noqa: BLE001
            logger.exception("worker_runtime shutdown failed")
        try:
            from secops.db import SessionLocal
            from secops.models import WorkerLease
            with SessionLocal() as db:
                active = db.query(WorkerLease).filter(WorkerLease.status == "active").all()
                for lease in active:
                    lease.status = "released"
                db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("lease release on shutdown failed")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Vantix",
        version="0.1.0",
        description="Codex-native Vantix backend for authorized CTF, KoTH, pentest, and bug bounty workflows.",
        lifespan=lifespan,
    )

    # Order matters: AuditMiddleware wraps innermost (runs last, sees final status);
    # RateLimitMiddleware next; RequestIdMiddleware outermost so all layers see request_id.
    app.add_middleware(AuditMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-Id", "X-CSRF-Token"],
    )

    @app.exception_handler(Exception)
    async def _generic_exception_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", "-")
        logger.exception("unhandled exception request_id=%s path=%s", request_id, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "internal error", "request_id": request_id},
            headers={"x-request-id": request_id},
        )

    app.include_router(health.router)
    app.include_router(auth.router)
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
    app.include_router(sources.router)

    if settings.enable_cve_mcp:
        from secops.mcp.cve_server import create_cve_mcp
        from secops.mcp.security import MCPAuthAndOriginMiddleware

        mcp_app = create_cve_mcp().streamable_http_app()
        app.mount(settings.cve_mcp_path, MCPAuthAndOriginMiddleware(mcp_app), name="cve-mcp")

    if settings.enable_vantix_mcp:
        from secops.mcp.security import MCPAuthAndOriginMiddleware
        from secops.mcp.vantix_server import create_vantix_mcp

        mcp_app = create_vantix_mcp().streamable_http_app()
        app.mount(settings.vantix_mcp_path, MCPAuthAndOriginMiddleware(mcp_app), name="vantix-mcp")

    dist_dir = Path(settings.frontend_root) / "dist"
    if dist_dir.exists():
        app.mount("/ui", StaticFiles(directory=dist_dir, html=True), name="ui")
    return app


app = create_app()
