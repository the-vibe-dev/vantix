from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from secops.config import settings
from secops.models import ProviderConfig

PROVIDER_TYPES = {"openai", "anthropic", "gemini", "ollama", "bedrock", "deepseek", "glm", "kimi", "qwen", "openrouter", "custom"}


class ProviderService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list(self) -> list[dict[str, Any]]:
        rows = self.db.execute(select(ProviderConfig).order_by(ProviderConfig.name.asc())).scalars().all()
        return [self.to_read(row) for row in rows]

    def get(self, provider_id: str) -> ProviderConfig | None:
        return self.db.get(ProviderConfig, provider_id)

    def upsert(self, payload: dict[str, Any]) -> ProviderConfig:
        provider_type = str(payload.get("provider_type", "")).strip().lower()
        if provider_type not in PROVIDER_TYPES:
            raise ValueError(f"Unsupported provider_type: {provider_type}")
        name = str(payload.get("name", "")).strip()
        if not name:
            raise ValueError("Provider name is required")
        row = self.db.execute(select(ProviderConfig).where(ProviderConfig.name == name)).scalar_one_or_none()
        if row is None:
            row = ProviderConfig(name=name, provider_type=provider_type)
            self.db.add(row)
        row.provider_type = provider_type
        row.base_url = str(payload.get("base_url") or "")
        row.default_model = str(payload.get("default_model") or "")
        row.enabled = bool(payload.get("enabled", False))
        row.metadata_json = dict(payload.get("metadata") or {})
        secret = str(payload.get("secret") or "")
        if secret:
            if not settings.secret_key:
                raise ValueError("Set VANTIX_SECRET_KEY or SECOPS_SECRET_KEY before storing provider secrets")
            row.encrypted_secret = encrypt_secret(secret, settings.secret_key)
        self.db.flush()
        return row

    def delete(self, provider_id: str) -> bool:
        row = self.get(provider_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.flush()
        return True

    def to_read(self, row: ProviderConfig) -> dict[str, Any]:
        return {
            "id": row.id,
            "name": row.name,
            "provider_type": row.provider_type,
            "base_url": row.base_url,
            "default_model": row.default_model,
            "enabled": row.enabled,
            "has_key": bool(row.encrypted_secret),
            "metadata": row.metadata_json or {},
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }


def encrypt_secret(secret: str, key: str) -> str:
    nonce = os.urandom(16)
    key_bytes = hashlib.sha256(key.encode("utf-8")).digest()
    data = secret.encode("utf-8")
    stream = _keystream(key_bytes, nonce, len(data))
    cipher = bytes(a ^ b for a, b in zip(data, stream))
    tag = hmac.new(key_bytes, nonce + cipher, hashlib.sha256).digest()
    return "v1:" + base64.urlsafe_b64encode(nonce + tag + cipher).decode("ascii")


def _keystream(key: bytes, nonce: bytes, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:size])
