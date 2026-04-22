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


def ensure_sqlite_compat_schema() -> None:
    db_path = _sqlite_path()
    if db_path is None:
        return
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        facts_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(facts)").fetchall()}
        if facts_columns:
            if "validated" not in facts_columns:
                conn.execute("ALTER TABLE facts ADD COLUMN validated BOOLEAN NOT NULL DEFAULT 0")
            if "fingerprint" not in facts_columns:
                conn.execute("ALTER TABLE facts ADD COLUMN fingerprint VARCHAR(64)")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_facts_fingerprint ON facts (fingerprint)")

        findings_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
        if findings_columns:
            if "fingerprint" not in findings_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64)")
            if "evidence_ids" not in findings_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN evidence_ids TEXT NOT NULL DEFAULT '[]'")
            if "reproduction_script" not in findings_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN reproduction_script TEXT NOT NULL DEFAULT ''")
            if "promoted_at" not in findings_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN promoted_at DATETIME")
            if "reviewed_at" not in findings_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN reviewed_at DATETIME")
            if "reviewer_user_id" not in findings_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN reviewer_user_id VARCHAR(36)")
            if "disposition" not in findings_columns:
                conn.execute("ALTER TABLE findings ADD COLUMN disposition VARCHAR(32) NOT NULL DEFAULT 'draft'")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_findings_run_fingerprint ON findings (run_id, fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_findings_reviewer_user_id ON findings (reviewer_user_id)")
        conn.commit()


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
