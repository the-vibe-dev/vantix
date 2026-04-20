from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import UploadFile

from secops.config import settings


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SourceIntakeService:
    def __init__(self) -> None:
        self.runtime_root = settings.runtime_root.resolve()
        self.upload_root = (self.runtime_root / "source_uploads").resolve()

    def _ensure_upload_root(self) -> None:
        self.upload_root.mkdir(parents=True, exist_ok=True)

    def stage_upload(self, upload: UploadFile) -> dict[str, Any]:
        self._ensure_upload_root()
        filename = Path(upload.filename or "source.zip").name
        if not filename.lower().endswith(".zip"):
            raise ValueError("Only .zip uploads are supported")
        max_bytes = max(1, int(settings.source_upload_max_mb)) * 1024 * 1024
        staged_id = f"src-{int(time.time())}-{hashlib.sha1(filename.encode('utf-8')).hexdigest()[:8]}"
        staged_dir = self.upload_root / staged_id
        staged_dir.mkdir(parents=True, exist_ok=False)
        archive_path = staged_dir / "payload.zip"
        sha = hashlib.sha256()
        size = 0
        with archive_path.open("wb") as handle:
            while True:
                chunk = upload.file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"Upload exceeds size limit ({settings.source_upload_max_mb}MB)")
                sha.update(chunk)
                handle.write(chunk)
        meta = {
            "staged_upload_id": staged_id,
            "filename": filename,
            "size_bytes": size,
            "sha256": sha.hexdigest(),
            "created_at": utcnow_iso(),
            "path": str(archive_path),
        }
        (staged_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return meta

    def resolve_for_run(self, *, workspace_root: Path, source_input: dict[str, Any]) -> dict[str, Any]:
        source_type = str(source_input.get("type", "none")).strip().lower()
        source_root = (workspace_root / "source").resolve()
        if source_root.exists():
            shutil.rmtree(source_root, ignore_errors=True)
        source_root.mkdir(parents=True, exist_ok=True)

        if source_type in {"", "none"}:
            return {"type": "none", "status": "skipped", "resolved_path": "", "ingested_at": utcnow_iso()}
        if source_type == "local":
            path = Path(str((source_input.get("local") or {}).get("path", ""))).expanduser().resolve()
            self._validate_local_path(path)
            return {"type": "local", "status": "ready", "resolved_path": str(path), "ingested_at": utcnow_iso()}
        if source_type == "github":
            github = source_input.get("github") or {}
            url = str(github.get("url", "")).strip()
            ref = str(github.get("ref", "")).strip()
            if not url.startswith("https://github.com/"):
                raise ValueError("GitHub source must use https://github.com/ URL")
            subprocess.run(["git", "clone", "--depth", "1", url, str(source_root)], check=True)
            if ref:
                subprocess.run(["git", "-C", str(source_root), "fetch", "--depth", "1", "origin", ref], check=True)
                subprocess.run(["git", "-C", str(source_root), "checkout", ref], check=True)
            return {"type": "github", "status": "ready", "url": url, "ref": ref, "resolved_path": str(source_root), "ingested_at": utcnow_iso()}
        if source_type == "upload":
            self._ensure_upload_root()
            upload = source_input.get("upload") or {}
            staged_id = str(upload.get("staged_upload_id", "")).strip()
            if not staged_id:
                raise ValueError("Missing staged_upload_id for upload source")
            archive_path = (self.upload_root / staged_id / "payload.zip").resolve()
            if not archive_path.is_file():
                raise ValueError(f"Staged upload not found: {staged_id}")
            self._extract_zip_safe(archive_path, source_root)
            return {"type": "upload", "status": "ready", "staged_upload_id": staged_id, "resolved_path": str(source_root), "ingested_at": utcnow_iso()}
        raise ValueError(f"Unsupported source type: {source_type}")

    def _validate_local_path(self, path: Path) -> None:
        if not path.exists() or not path.is_dir():
            raise ValueError(f"Local source path does not exist: {path}")
        allowed = [root.resolve() for root in settings.source_allowed_roots]
        for root in allowed:
            try:
                path.relative_to(root)
                return
            except ValueError:
                continue
        raise ValueError("Local source path is outside allowed roots")

    def _extract_zip_safe(self, archive_path: Path, dest: Path) -> None:
        dest = dest.resolve()
        with zipfile.ZipFile(archive_path) as zf:
            for member in zf.infolist():
                out = (dest / member.filename).resolve()
                try:
                    out.relative_to(dest)
                except ValueError as exc:
                    raise ValueError("Unsafe zip path detected") from exc
            zf.extractall(dest)
