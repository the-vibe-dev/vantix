"""Restore settings between security tests so globals don't leak into other modules."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _restore_settings():
    from secops.config import settings

    fields = ("api_token", "dev_mode", "service_token_enabled")
    originals = {k: getattr(settings, k) for k in fields}
    yield
    for key, value in originals.items():
        object.__setattr__(settings, key, value)
