"""P1-7 — fixture-driven auth flow against DVWA / Juice Shop HTML shapes.

Drives ``BrowserRuntimeService._perform_login`` with HTML payloads lifted from
vendored fixture pages so the test mirrors the DOM Vantix will actually meet
in live engagements. No real browser dependency; Playwright is replaced by a
fake page/context pair that replays the fixture HTML across the pre-auth /
post-auth lifecycle the method expects.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from secops.services.browser_runtime import (
    BrowserAuthConfig,
    BrowserPolicy,
    BrowserRuntimeService,
)

FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "browser_sites"


class _ScriptedPage:
    """Minimal page that returns fixture HTML before/after the auth submit."""

    def __init__(self, *, pre_html: str, post_html: str, login_url: str, home_url: str) -> None:
        self._pre = pre_html
        self._post = post_html
        self._login_url = login_url
        self._home_url = home_url
        self._url = login_url
        self._submitted = False
        self.calls: list[tuple[str, tuple, dict]] = []

    def goto(self, url: str, **kwargs: Any) -> None:
        self.calls.append(("goto", (url,), kwargs))
        self._url = url

    def content(self) -> str:
        return self._post if self._submitted else self._pre

    def title(self) -> str:
        return "Home" if self._submitted else "Login"

    @property
    def url(self) -> str:
        return self._url

    def fill(self, selector: str, value: str) -> None:
        self.calls.append(("fill", (selector, value), {}))

    def click(self, selector: str) -> None:
        self.calls.append(("click", (selector,), {}))
        self._submitted = True
        self._url = self._home_url

    def press(self, selector: str, key: str) -> None:
        self.calls.append(("press", (selector, key), {}))
        self._submitted = True
        self._url = self._home_url

    def wait_for_timeout(self, ms: int) -> None:
        self.calls.append(("wait", (ms,), {}))

    def evaluate(self, script: str, *args: Any) -> int:
        if "localStorage" in script:
            return 3 if self._submitted else 0
        if "sessionStorage" in script:
            return 1 if self._submitted else 0
        return 0


class _ScriptedContext:
    def __init__(self) -> None:
        self._cookies: list[dict[str, Any]] = []

    def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
        self._cookies.extend(cookies)

    def cookies(self) -> list[dict[str, Any]]:
        # Fake a session cookie appearing after auth submit.
        return list(self._cookies) + [
            {"name": "PHPSESSID", "value": "z", "httpOnly": True, "secure": True}
        ]


@pytest.mark.parametrize(
    "site,login_file,home_file,username_sel,password_sel,submit_sel,user,pw",
    [
        (
            "dvwa",
            "dvwa_login.html",
            "dvwa_home.html",
            "#user",
            "#pass",
            "#submit-btn",
            "admin",
            "password",
        ),
        (
            "juice_shop",
            "juice_shop_login.html",
            "juice_shop_home.html",
            "#email",
            "#password",
            "#loginButton",
            "alice@juice-sh.op",
            "s3cret",
        ),
    ],
)
def test_perform_login_against_vendor_fixture(
    site: str,
    login_file: str,
    home_file: str,
    username_sel: str,
    password_sel: str,
    submit_sel: str,
    user: str,
    pw: str,
) -> None:
    pre_html = (FIXTURE_ROOT / login_file).read_text(encoding="utf-8")
    post_html = (FIXTURE_ROOT / home_file).read_text(encoding="utf-8")
    svc = BrowserRuntimeService()
    page = _ScriptedPage(
        pre_html=pre_html,
        post_html=post_html,
        login_url="https://app.test/login",
        home_url="https://app.test/home",
    )
    context = _ScriptedContext()
    policy = BrowserPolicy(
        allowed_origins=["https://app.test"],
        allow_auth=True,
        allow_form_submission=True,
    )
    auth_cfg = BrowserAuthConfig(
        login_url="https://app.test/login",
        username=user,
        password=pw,
        username_selector=username_sel,
        password_selector=password_sel,
        submit_selector=submit_sel,
        role_label=f"{site}-operator",
    )

    state, transitions, diffs = svc._perform_login(
        page=page,
        context=context,
        policy=policy,
        auth_cfg=auth_cfg,
        entry_url="https://app.test/",
    )

    assert state == "success", f"{site} fixture should produce a successful login"
    # Both username and password selectors were filled in.
    filled = [c for c in page.calls if c[0] == "fill"]
    assert (username_sel, user) in {(c[1][0], c[1][1]) for c in filled}
    assert (password_sel, pw) in {(c[1][0], c[1][1]) for c in filled}
    # Submit was clicked exactly once against the configured selector.
    clicks = [c for c in page.calls if c[0] == "click"]
    assert clicks and clicks[0][1][0] == submit_sel
    # Transition log includes both lifecycle stages and a diff.
    stages = [t.get("stage") for t in transitions]
    assert stages.count("pre-auth") == 1
    assert stages.count("post-auth") == 1
    assert diffs and diffs[0]["stage"] == "auth-transition"
    # Post-auth URL reflects the navigation to the home fixture.
    post = next(t for t in transitions if t.get("stage") == "post-auth")
    assert post["url"].endswith("/home")
