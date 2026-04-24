from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"secops_contentblob_test_{os.getpid()}.db"
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

import pytest

from secops.db import Base, SessionLocal, engine
from secops.models import ContentBlob
from secops.replay.cache import exists, load, sha256_hex, store


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def test_store_returns_sha256_and_persists():
    data = b"hello vantix"
    with SessionLocal() as db:
        digest = store(db, data, content_type="text/plain")
        db.commit()
    assert digest == sha256_hex(data)
    with SessionLocal() as db:
        blob = db.get(ContentBlob, digest)
        assert blob is not None
        assert bytes(blob.data) == data
        assert blob.content_type == "text/plain"
        assert blob.size_bytes == len(data)


def test_store_is_idempotent():
    data = b"duplicate payload"
    with SessionLocal() as db:
        d1 = store(db, data)
        d2 = store(db, data)
        db.commit()
    assert d1 == d2
    with SessionLocal() as db:
        rows = db.query(ContentBlob).filter(ContentBlob.sha256 == d1).count()
    assert rows == 1


def test_load_and_exists():
    payload = b"{\"k\":\"v\"}"
    with SessionLocal() as db:
        digest = store(db, payload, content_type="application/json")
        db.commit()
    with SessionLocal() as db:
        assert exists(db, digest) is True
        assert load(db, digest) == payload
        assert load(db, "0" * 64) is None
