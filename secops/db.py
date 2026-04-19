from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import sqlite3

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from secops.config import settings


class Base(DeclarativeBase):
    pass


def _sqlite_path() -> Path | None:
    if not settings.database_url.startswith("sqlite"):
        return None
    db_path = settings.database_url.replace("sqlite+pysqlite:///", "", 1)
    if not db_path or db_path == ":memory:":
        return None
    return Path(db_path)


def _recover_sqlite_if_needed() -> None:
    db_path = _sqlite_path()
    if db_path is None:
        return
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if not db_path.exists():
        return
    ok = False
    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute("PRAGMA quick_check").fetchone()
            ok = bool(row and row[0] == "ok")
    except sqlite3.DatabaseError:
        ok = False
    if ok:
        return
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    backup = db_path.with_name(f"{db_path.name}.corrupt-{stamp}")
    db_path.rename(backup)


def _build_engine():
    _recover_sqlite_if_needed()
    db_path = _sqlite_path()
    if db_path is not None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    connect_args = {"check_same_thread": False, "timeout": 30} if settings.database_url.startswith("sqlite") else {}
    engine = create_engine(settings.database_url, future=True, connect_args=connect_args, pool_pre_ping=True)
    if settings.database_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def set_sqlite_pragmas(dbapi_connection, _connection_record):  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return engine


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
