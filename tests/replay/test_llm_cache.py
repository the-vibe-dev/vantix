"""V2-11 — LLM cache content-addressed store/lookup."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_llm_cache_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.db import Base, SessionLocal, engine
from secops.models import ContentBlob, LlmCacheEntry
from secops.replay import llm_cache


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


MODEL = "claude-opus-4-7"
PARAMS = {"temperature": 0.0, "top_p": 1.0, "max_tokens": 512}
PROMPT = [{"role": "user", "content": "what services are exposed?"}]


def test_miss_then_hit_round_trip():
    with SessionLocal() as db:
        assert llm_cache.lookup(db, model=MODEL, params=PARAMS, prompt=PROMPT) is None
        key = llm_cache.store(db, model=MODEL, params=PARAMS, prompt=PROMPT, response=b'{"ok":1}')
        db.commit()

    with SessionLocal() as db:
        hit = llm_cache.lookup(db, model=MODEL, params=PARAMS, prompt=PROMPT)
    assert hit is not None
    assert hit.key_sha256 == key
    assert hit.response_bytes == b'{"ok":1}'


def test_key_stable_under_param_order():
    k1 = llm_cache.compute_key(
        model=MODEL,
        params_sha256=llm_cache.canonical_sha256({"a": 1, "b": 2}),
        prompt_sha256=llm_cache.canonical_sha256(PROMPT),
    )
    k2 = llm_cache.compute_key(
        model=MODEL,
        params_sha256=llm_cache.canonical_sha256({"b": 2, "a": 1}),
        prompt_sha256=llm_cache.canonical_sha256(PROMPT),
    )
    assert k1 == k2


def test_different_model_produces_different_key():
    with SessionLocal() as db:
        llm_cache.store(db, model=MODEL, params=PARAMS, prompt=PROMPT, response=b"A")
        llm_cache.store(db, model="claude-sonnet-4-6", params=PARAMS, prompt=PROMPT, response=b"B")
        db.commit()
        hit_a = llm_cache.lookup(db, model=MODEL, params=PARAMS, prompt=PROMPT)
        hit_b = llm_cache.lookup(db, model="claude-sonnet-4-6", params=PARAMS, prompt=PROMPT)
    assert hit_a.response_bytes == b"A"
    assert hit_b.response_bytes == b"B"
    assert hit_a.key_sha256 != hit_b.key_sha256


def test_idempotent_store_same_response():
    with SessionLocal() as db:
        k1 = llm_cache.store(db, model=MODEL, params=PARAMS, prompt=PROMPT, response=b"same")
        k2 = llm_cache.store(db, model=MODEL, params=PARAMS, prompt=PROMPT, response=b"same")
        db.commit()
        assert k1 == k2
        assert db.query(LlmCacheEntry).count() == 1
        assert db.query(ContentBlob).count() == 1


def test_conflicting_response_rejected():
    with SessionLocal() as db:
        llm_cache.store(db, model=MODEL, params=PARAMS, prompt=PROMPT, response=b"one")
        db.commit()
        with pytest.raises(ValueError, match="key collision"):
            llm_cache.store(db, model=MODEL, params=PARAMS, prompt=PROMPT, response=b"two")


def test_orphan_blob_reports_miss():
    with SessionLocal() as db:
        llm_cache.store(db, model=MODEL, params=PARAMS, prompt=PROMPT, response=b"gone")
        db.commit()
    # Manually wipe the blob to simulate GC
    with SessionLocal() as db:
        db.query(ContentBlob).delete()
        db.commit()
    with SessionLocal() as db:
        assert llm_cache.lookup(db, model=MODEL, params=PARAMS, prompt=PROMPT) is None
