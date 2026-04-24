"""Content-addressed LLM call cache (V2-11).

Keying is strict so replays are bit-identical: the cache key is
``sha256(model || "\0" || params_sha256 || "\0" || prompt_sha256)``
where ``params_sha256`` and ``prompt_sha256`` are each a sha256 over a
canonical-JSON dump (sorted keys, tight separators). The response body
is stored as a ``ContentBlob`` and referenced by sha256.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from secops.models import LlmCacheEntry
from secops.replay.cache import load as blob_load
from secops.replay.cache import sha256_hex as blob_sha256
from secops.replay.cache import store as blob_store


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(_canonical_json(obj)).hexdigest()


def compute_key(*, model: str, params_sha256: str, prompt_sha256: str) -> str:
    material = b"\0".join([model.encode("utf-8"), params_sha256.encode("ascii"), prompt_sha256.encode("ascii")])
    return hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class LlmCacheHit:
    key_sha256: str
    response_blob_sha256: str
    response_bytes: bytes


def lookup(
    db: Session,
    *,
    model: str,
    params: Any,
    prompt: Any,
) -> LlmCacheHit | None:
    """Return a cache hit for ``(model, params, prompt)`` or ``None``."""
    params_sha = canonical_sha256(params)
    prompt_sha = canonical_sha256(prompt)
    key = compute_key(model=model, params_sha256=params_sha, prompt_sha256=prompt_sha)
    entry = db.get(LlmCacheEntry, key)
    if entry is None:
        return None
    data = blob_load(db, entry.response_blob_sha256)
    if data is None:
        # Blob GC'd or manually deleted — treat as a miss.
        return None
    return LlmCacheHit(
        key_sha256=key,
        response_blob_sha256=entry.response_blob_sha256,
        response_bytes=data,
    )


def store(
    db: Session,
    *,
    model: str,
    params: Any,
    prompt: Any,
    response: bytes,
    content_type: str = "application/json",
) -> str:
    """Persist a cache entry and return its key. Idempotent per key."""
    params_sha = canonical_sha256(params)
    prompt_sha = canonical_sha256(prompt)
    key = compute_key(model=model, params_sha256=params_sha, prompt_sha256=prompt_sha)
    resp_sha = blob_store(db, response, content_type=content_type)
    existing = db.get(LlmCacheEntry, key)
    if existing is not None:
        # Key already present — must map to the same response for strict replay.
        if existing.response_blob_sha256 != resp_sha:
            raise ValueError(
                f"llm_cache: key collision with different response; key={key[:12]}"
            )
        return key
    db.add(
        LlmCacheEntry(
            key_sha256=key,
            model=model,
            params_sha256=params_sha,
            prompt_sha256=prompt_sha,
            response_blob_sha256=resp_sha,
        )
    )
    db.flush()
    return key


__all__ = [
    "LlmCacheHit",
    "canonical_sha256",
    "compute_key",
    "lookup",
    "store",
    "blob_sha256",
]
