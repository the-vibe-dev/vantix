"""Fingerprint helper for vector/finding dedup.

A fingerprint identifies a logical vulnerability irrespective of wording or minor
re-execution differences. Two findings with the same fingerprint are duplicates.

Canonical form: sha256 of `|`-joined, lowercased, trimmed components:
  (vector_kind, target_host, target_path, target_param, cwe)

Missing components use the sentinel `-`.
"""
from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlsplit


def _norm(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text or "-"


def compute_fingerprint(
    *,
    vector_kind: str | None = None,
    target_host: str | None = None,
    target_path: str | None = None,
    target_param: str | None = None,
    cwe: str | None = None,
) -> str:
    parts = [_norm(vector_kind), _norm(target_host), _norm(target_path), _norm(target_param), _norm(cwe)]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:32]


def fingerprint_from_meta(meta: dict[str, Any], *, fact_kind: str = "") -> str:
    """Derive a fingerprint from a Fact's metadata_json.

    Looks for common keys: url, target, path, param, parameter, cwe, vulnerability_class.
    Falls back to best-effort component extraction from a URL.
    """
    vector_kind = str(meta.get("vulnerability_class") or meta.get("kind") or fact_kind or "").strip()
    cwe = str(meta.get("cwe") or meta.get("CWE") or "").strip()
    param = str(meta.get("param") or meta.get("parameter") or "").strip()

    host = str(meta.get("host") or meta.get("target_host") or meta.get("target") or "").strip()
    path = str(meta.get("path") or meta.get("target_path") or "").strip()

    url = str(meta.get("url") or meta.get("endpoint") or "").strip()
    if url:
        parsed = urlsplit(url)
        if parsed.netloc and not host:
            host = parsed.netloc
        if parsed.path and not path:
            path = parsed.path

    return compute_fingerprint(
        vector_kind=vector_kind,
        target_host=host,
        target_path=path,
        target_param=param,
        cwe=cwe,
    )
