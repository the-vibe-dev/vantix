"""Content-addressed blob cache backed by the ``content_blobs`` table.

The replay layer pins every LLM prompt/response and tool stdout/stderr
payload as a ``ContentBlob`` keyed by sha256. This module provides the
minimal read/write helpers; higher-level caches (LLM cache, tool-call
cache) layer on top in later phases.
"""

from __future__ import annotations

import hashlib

from sqlalchemy.orm import Session

from secops.models import ContentBlob


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def store(db: Session, data: bytes, *, content_type: str = "application/octet-stream") -> str:
    """Persist ``data`` and return its sha256. Idempotent: existing rows are reused."""
    digest = sha256_hex(data)
    existing = db.get(ContentBlob, digest)
    if existing is not None:
        return digest
    db.add(
        ContentBlob(
            sha256=digest,
            content_type=content_type,
            size_bytes=len(data),
            data=data,
        )
    )
    db.flush()
    return digest


def load(db: Session, digest: str) -> bytes | None:
    blob = db.get(ContentBlob, digest)
    return None if blob is None else bytes(blob.data)


def exists(db: Session, digest: str) -> bool:
    return db.get(ContentBlob, digest) is not None
