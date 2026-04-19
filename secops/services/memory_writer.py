from __future__ import annotations

import fcntl
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from secops.config import settings
from secops.models import MemoryEvent, WorkspaceRun


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _compact_text(value: Any, repo_root: Path | None = None, runtime_root: Path | None = None) -> str:
    text = str(value)
    replacements = [
        (str(runtime_root or settings.runtime_root), "${SECOPS_RUNTIME_ROOT}"),
        (str(repo_root or settings.repo_root), "${CTF_ROOT}"),
        (str(Path.home()), "${HOME}"),
    ]
    for raw, marker in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if raw:
            text = text.replace(raw, marker)
    return text


def _compact_fact(value: Any, repo_root: Path | None = None, runtime_root: Path | None = None) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [_compact_text(part, repo_root=repo_root, runtime_root=runtime_root) for part in value[:2]]


@dataclass
class DenseMemoryRecord:
    mode: str = "checkpoint"
    objective: str = ""
    done: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    next_action: str = ""
    files: list[str] = field(default_factory=list)
    facts: list[list[str]] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    phase: str = ""
    session_id: str = ""
    run_id: str = ""
    agent: str = ""


class MemoryWriteService:
    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = (repo_root or settings.repo_root).resolve()
        self.runtime_root = settings.runtime_root.resolve()
        self.memory_root = self.repo_root / "memory"
        self.session_root = self.memory_root / "sessions"
        self.index_file = self.memory_root / "session_index.jsonl"
        self.lock_file = self.memory_root / ".memory.lock"
        self.legacy_journal = self.memory_root / "session_journal.md"
        self.legacy_handoff = self.memory_root / "compaction_handoffs.md"

    def write(self, record: DenseMemoryRecord | dict[str, Any], db: Session | None = None) -> dict[str, Any]:
        if isinstance(record, dict):
            record = DenseMemoryRecord(**record)
        self.memory_root.mkdir(parents=True, exist_ok=True)
        self.session_root.mkdir(parents=True, exist_ok=True)
        session_id = record.session_id or self._session_id(record.run_id)
        agent = record.agent or os.getenv("CODEX_AGENT_ID") or f"local:{os.getpid()}"
        payload = {
            "v": 1,
            "ts": utc_ts(),
            "sid": session_id,
            "run_id": record.run_id,
            "agent": _compact_text(agent, self.repo_root, self.runtime_root),
            "mode": _compact_text(record.mode, self.repo_root, self.runtime_root),
            "phase": _compact_text(record.phase, self.repo_root, self.runtime_root),
            "ctx": [_compact_text(item, self.repo_root, self.runtime_root) for item in _list(record.context)],
            "obj": _compact_text(record.objective, self.repo_root, self.runtime_root),
            "done": [_compact_text(item, self.repo_root, self.runtime_root) for item in _list(record.done)],
            "facts": [fact for fact in (_compact_fact(item, self.repo_root, self.runtime_root) for item in _list(record.facts)) if fact],
            "issues": [_compact_text(item, self.repo_root, self.runtime_root) for item in _list(record.issues)],
            "next": _compact_text(record.next_action, self.repo_root, self.runtime_root),
            "files": [_compact_text(item, self.repo_root, self.runtime_root) for item in _list(record.files)],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        paths: list[str] = []

        with self.lock_file.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            seq = self._next_sequence(session_id)
            payload["seq"] = seq
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            paths.append(str(self._append_jsonl(self.index_file, payload)))
            session_dir = self.session_root / session_id
            session_dir.mkdir(parents=True, exist_ok=True)
            paths.append(str(self._append_jsonl(session_dir / "journal.jsonl", payload)))
            paths.append(str(self._append_markdown(self.legacy_journal, payload, handoff=False)))
            if record.mode in {"handoff", "close", "failure"}:
                paths.append(str(self._append_markdown(self.legacy_handoff, payload, handoff=True)))
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

        db_event = self._write_db_event(db, record, encoded) if db is not None else {"attempted": False, "ok": False}

        return {
            "ok": True,
            "ts": payload["ts"],
            "session_id": session_id,
            "run_id": record.run_id,
            "seq": payload["seq"],
            "paths": paths,
            "sha256": digest,
            "db_event": db_event,
        }

    def latest(self) -> dict[str, Any] | None:
        if not self.index_file.exists():
            return None
        last = ""
        for raw in self.index_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if raw.strip():
                last = raw.strip()
        if not last:
            return None
        try:
            return json.loads(last)
        except json.JSONDecodeError:
            return None

    def health(self, stale_minutes: int = 30) -> dict[str, Any]:
        latest = self.latest()
        if latest is None:
            return {"ok": False, "reason": "no-memory-records", "latest": None}
        ts = latest.get("ts", "")
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            age_seconds = (datetime.now(timezone.utc) - parsed).total_seconds()
        except ValueError:
            return {"ok": False, "reason": "bad-latest-timestamp", "latest": latest}
        return {"ok": age_seconds <= stale_minutes * 60, "age_seconds": int(age_seconds), "stale_minutes": stale_minutes, "latest": latest}

    def _session_id(self, run_id: str = "") -> str:
        if run_id:
            return f"run-{run_id[:12]}"
        return f"s-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid4().hex[:8]}"

    def _write_db_event(self, db: Session, record: DenseMemoryRecord, encoded: str) -> dict[str, Any]:
        if not record.run_id:
            return {"attempted": False, "ok": False, "reason": "missing-run-id"}
        if db.in_transaction():
            return {"attempted": False, "ok": False, "reason": "caller-transaction-open"}
        bind = db.get_bind()
        EventSession = sessionmaker(bind=bind, autoflush=False, autocommit=False, future=True)
        try:
            with EventSession() as event_db:
                if event_db.get(WorkspaceRun, record.run_id) is None:
                    return {"attempted": True, "ok": False, "reason": "run-not-committed"}
                event_db.add(
                    MemoryEvent(
                        run_id=record.run_id,
                        classification=record.mode,
                        source="dense-memory",
                        content=encoded,
                        tags=[str(item) for item in _list(record.context)],
                    )
                )
                event_db.commit()
            return {"attempted": True, "ok": True}
        except SQLAlchemyError as exc:
            return {"attempted": True, "ok": False, "reason": exc.__class__.__name__}

    def _next_sequence(self, session_id: str) -> int:
        path = self.session_root / session_id / "journal.jsonl"
        if not path.exists():
            return 1
        return sum(1 for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines() if raw.strip()) + 1

    def _append_jsonl(self, path: Path, payload: dict[str, Any]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return path

    def _append_markdown(self, path: Path, payload: dict[str, Any], *, handoff: bool) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            title = "Dense Handoffs" if handoff else "Dense Session Journal"
            path.write_text(
                f"# {title}\n\n"
                "fmt: ts=<utc> sid=<id> run=<id> agent=<id> mode=<mode> phase=<phase> ctx=[] obj=[] done=[] issues=[] next=[] files=[] seq=<n>\n",
                encoding="utf-8",
            )
        line = self._dense_markdown_line(payload)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return path

    def _dense_markdown_line(self, payload: dict[str, Any]) -> str:
        def arr(key: str) -> str:
            values = payload.get(key, [])
            if isinstance(values, str):
                values = [values]
            cleaned = [str(item).replace("\n", " ").replace("|", "/").strip()[:180] for item in values if str(item).strip()]
            return "[" + ";".join(cleaned) + "]"

        obj = str(payload.get("obj", "")).replace("\n", " ").strip()[:220]
        next_action = str(payload.get("next", "")).replace("\n", " ").strip()[:220]
        return (
            f"ts={payload.get('ts', '')} sid={payload.get('sid', '')} run={payload.get('run_id', '')} "
            f"agent={payload.get('agent', '')} mode={payload.get('mode', '')} phase={payload.get('phase', '')} "
            f"ctx={arr('ctx')} obj=[{obj}] done={arr('done')} issues={arr('issues')} "
            f"next=[{next_action}] files={arr('files')} seq={payload.get('seq', '')}"
        )
