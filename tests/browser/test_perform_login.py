"""P1-3 — ``BrowserRuntimeService._perform_login`` unit coverage.

Tests the extracted login flow directly with fake Playwright-like page/context
objects. Avoids any real browser dependency so the refactor is testable in CI.
Also covers the session-state path helper so the on-disk layout for
``(engagement_id, role_label)`` scoping is deterministic.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from secops.services.browser_runtime import (
    BrowserAuthConfig,
    BrowserPolicy,
    BrowserRuntimeService,
)


class _FakePage:
    def __init__(self, *, pre_html: str, post_html: str, url_after: str = "https://app.test/home") -> None:
        self._html_queue = [pre_html, post_html]
        self._url = "https://app.test/login"
        self._url_after = url_after
        self.calls: list[tuple[str, tuple, dict]] = []
        self._filled_once = False

    def goto(self, url: str, **kwargs: Any) -> None:
        self.calls.append(("goto", (url,), kwargs))
        self._url = url

    def content(self) -> str:
        return self._html_queue.pop(0) if self._html_queue else ""

    def title(self) -> str:
        return "Login" if "login" in self._url else "Home"

    @property
    def url(self) -> str:
        return self._url

    def fill(self, selector: str, value: str) -> None:
        self.calls.append(("fill", (selector, value), {}))
        self._filled_once = True

    def click(self, selector: str) -> None:
        self.calls.append(("click", (selector,), {}))
        # Simulate redirect after successful submit.
        self._url = self._url_after

    def press(self, selector: str, key: str) -> None:
        self.calls.append(("press", (selector, key), {}))
        self._url = self._url_after

    def wait_for_timeout(self, ms: int) -> None:
        self.calls.append(("wait", (ms,), {}))

    def evaluate(self, script: str, *args: Any) -> int:
        # Two fake storage keys after auth to indicate session got populated.
        if "localStorage" in script:
            return 2 if self._filled_once else 0
        if "sessionStorage" in script:
            return 1 if self._filled_once else 0
        return 0


class _FakeContext:
    def __init__(self) -> None:
        self._cookies: list[dict[str, Any]] = []
        self.add_cookies_calls: list[list[dict[str, Any]]] = []

    def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
        self._cookies.extend(cookies)
        self.add_cookies_calls.append(cookies)

    def cookies(self) -> list[dict[str, Any]]:
        # Return more cookies after submit to trigger success heuristic.
        return list(self._cookies) + ([{"name": "session", "httpOnly": True, "secure": True}] if self._cookies or True else [])


def _policy(allow_form_submission: bool = True) -> BrowserPolicy:
    return BrowserPolicy(
        allowed_origins=["https://app.test"],
        allow_auth=True,
        allow_form_submission=allow_form_submission,
    )


def _auth_cfg(steps: list[dict[str, Any]] | None = None, role: str = "admin") -> BrowserAuthConfig:
    return BrowserAuthConfig(
        login_url="https://app.test/login",
        username="alice",
        password="s3cret",
        steps=steps or [],
        role_label=role,
    )


def test_session_state_path_is_stable_per_engagement_role(tmp_path: Path) -> None:
    svc = BrowserRuntimeService()
    a = svc._session_state_path(tmp_path, "engagement-123|admin")
    b = svc._session_state_path(tmp_path, "engagement-123|admin")
    c = svc._session_state_path(tmp_path, "engagement-123|auditor")
    assert a == b
    assert a != c
    # Stored under the hashed-key layout.
    expected_digest = hashlib.sha256(b"engagement-123|admin").hexdigest()[:32]
    assert a.name == f"{expected_digest}.json"
    assert a.parent.name == ".browser_sessions"
    assert a.parent.exists()


def test_perform_login_credential_flow_marks_success() -> None:
    svc = BrowserRuntimeService()
    page = _FakePage(
        pre_html="<html><body><form><input type='password'/></form></body></html>",
        post_html="<html><body>Welcome</body></html>",
    )
    context = _FakeContext()

    state, transitions, diffs = svc._perform_login(
        page=page,
        context=context,
        policy=_policy(),
        auth_cfg=_auth_cfg(),
        entry_url="https://app.test/",
    )

    assert state == "success"
    # Filled both username and password and clicked submit.
    filled = [c for c in page.calls if c[0] == "fill"]
    clicked = [c for c in page.calls if c[0] == "click"]
    assert len(filled) == 2
    assert len(clicked) == 1
    # Pre-auth and post-auth transitions are both recorded.
    stages = [t.get("stage") for t in transitions]
    assert "pre-auth" in stages
    assert "post-auth" in stages
    assert diffs and diffs[0]["stage"] == "auth-transition"


def test_perform_login_blocked_submit_is_partial() -> None:
    svc = BrowserRuntimeService()
    page = _FakePage(
        pre_html="<html><body><form><input type='password'/></form></body></html>",
        post_html="<html><body><form><input type='password'/></form></body></html>",
    )
    context = _FakeContext()

    state, transitions, _ = svc._perform_login(
        page=page,
        context=context,
        policy=_policy(allow_form_submission=False),
        auth_cfg=_auth_cfg(),
        entry_url="https://app.test/",
    )

    assert state == "partial"
    # Submit click never happened when form submission is blocked.
    assert not any(c[0] == "click" for c in page.calls)


def test_perform_login_steps_dispatch_fill_click_goto_wait() -> None:
    svc = BrowserRuntimeService()
    page = _FakePage(
        pre_html="<html><body><form><input type='password'/></form></body></html>",
        post_html="<html><body>OK</body></html>",
    )
    context = _FakeContext()

    steps = [
        {"action": "goto", "url": "${login_url}"},
        {"action": "fill", "selector": "#u", "value": "${username}"},
        {"action": "fill", "selector": "#p", "value": "${password}"},
        {"action": "click", "selector": "#submit"},
        {"action": "wait", "ms": 500},
    ]
    state, _, _ = svc._perform_login(
        page=page,
        context=context,
        policy=_policy(),
        auth_cfg=_auth_cfg(steps=steps),
        entry_url="https://app.test/",
    )
    actions = [c[0] for c in page.calls]
    # goto(login_url) from the outer pre-auth + goto from the goto step.
    assert actions.count("goto") >= 2
    assert ("fill", ("#u", "alice"), {}) in page.calls
    assert ("fill", ("#p", "s3cret"), {}) in page.calls
    assert ("click", ("#submit",), {}) in page.calls
    assert ("wait", (500,), {}) in page.calls
    assert state in {"success", "partial"}


def test_perform_login_disallowed_url_returns_failed() -> None:
    svc = BrowserRuntimeService()
    page = _FakePage(pre_html="", post_html="")
    context = _FakeContext()
    auth_cfg = _auth_cfg()
    auth_cfg.login_url = "https://other.example/login"  # not in allowed_origins
    state, transitions, _ = svc._perform_login(
        page=page,
        context=context,
        policy=_policy(),
        auth_cfg=auth_cfg,
        entry_url="https://app.test/",
    )
    assert state == "failed"
    assert transitions == []
    # Did not attempt navigation.
    assert not any(c[0] == "goto" for c in page.calls)


def test_perform_login_applies_session_cookies() -> None:
    svc = BrowserRuntimeService()
    page = _FakePage(
        pre_html="<html><body>hi</body></html>",
        post_html="<html><body>bye</body></html>",
    )
    context = _FakeContext()
    auth_cfg = _auth_cfg()
    auth_cfg.session_cookies = [{"name": "sid", "value": "abc", "domain": "app.test"}]

    _, transitions, _ = svc._perform_login(
        page=page,
        context=context,
        policy=_policy(),
        auth_cfg=auth_cfg,
        entry_url="https://app.test/",
    )
    stages = [t.get("stage") for t in transitions]
    assert "cookie-import" in stages
    assert context.add_cookies_calls, "session cookies should be applied to context"
