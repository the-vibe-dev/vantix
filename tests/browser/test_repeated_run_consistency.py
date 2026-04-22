"""P1-7 — repeated-run consistency for browser session reuse.

Exercises the on-disk layout used by ``BrowserRuntimeService.assess`` so a
second run against the same ``(engagement_id, role_label)`` reuses the saved
``storage_state`` rather than re-authenticating. The heavy Playwright plumbing
is not replayed here — the invariant under test is the deterministic session
path plus the file being present and reusable after a first run writes it.
"""
from __future__ import annotations

import json
from pathlib import Path

from secops.services.browser_runtime import BrowserRuntimeService


def _write_storage_state(path: Path) -> None:
    # Shape matches what Playwright's ``context.storage_state`` produces.
    payload = {
        "cookies": [
            {"name": "sid", "value": "abc", "domain": "app.test", "path": "/"},
        ],
        "origins": [
            {
                "origin": "https://app.test",
                "localStorage": [{"name": "token", "value": "tk"}],
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_session_state_path_stable_across_runs(tmp_path: Path) -> None:
    svc = BrowserRuntimeService()
    key = "engagement-xyz|admin"
    first = svc._session_state_path(tmp_path, key)
    second = svc._session_state_path(tmp_path, key)
    assert first == second
    assert first.parent.exists()


def test_second_run_consumes_stored_state(tmp_path: Path) -> None:
    svc = BrowserRuntimeService()
    key = "engagement-xyz|admin"
    first = svc._session_state_path(tmp_path, key)
    _write_storage_state(first)

    # Simulate the second-run decision made inside ``assess``: if the
    # deterministic session file exists, storage_state should be loaded.
    resolved = svc._session_state_path(tmp_path, key)
    assert resolved == first
    assert resolved.exists()
    loaded = json.loads(resolved.read_text(encoding="utf-8"))
    assert loaded["cookies"][0]["name"] == "sid"
    assert loaded["origins"][0]["origin"] == "https://app.test"


def test_different_role_labels_do_not_share_state(tmp_path: Path) -> None:
    svc = BrowserRuntimeService()
    admin_path = svc._session_state_path(tmp_path, "engagement-xyz|admin")
    auditor_path = svc._session_state_path(tmp_path, "engagement-xyz|auditor")
    _write_storage_state(admin_path)
    assert admin_path != auditor_path
    assert admin_path.exists()
    assert not auditor_path.exists()


def test_different_engagements_do_not_share_state(tmp_path: Path) -> None:
    svc = BrowserRuntimeService()
    a = svc._session_state_path(tmp_path, "engagement-A|admin")
    b = svc._session_state_path(tmp_path, "engagement-B|admin")
    _write_storage_state(a)
    assert a != b
    assert a.exists()
    assert not b.exists()
