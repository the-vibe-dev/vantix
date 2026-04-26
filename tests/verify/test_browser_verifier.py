from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secops.verify import ReplaySpec, VerifyContext, default_registry
from secops.verify.browser import BrowserVerifier


@dataclass
class _FakeObs:
    url: str
    title: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _FakeResult:
    observations: list[_FakeObs]
    blocked_actions: list[str] = field(default_factory=list)
    current_url: str = ""
    authenticated: str = "anonymous"


class _FakeRuntime:
    def __init__(self, result: _FakeResult, *, raise_exc: Exception | None = None) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []
        self.raise_exc = raise_exc

    def assess(self, *, entry_url: str, run_config: dict[str, Any], workspace_root: Any = None) -> _FakeResult:
        self.calls.append({"entry_url": entry_url, "run_config": run_config})
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.result


def _ctx(runtime: _FakeRuntime) -> VerifyContext:
    return VerifyContext(extras={"browser_runtime": runtime})


def test_browser_happy_path():
    runtime = _FakeRuntime(
        _FakeResult(
            observations=[
                _FakeObs(url="https://target/", title="Home", links=["/a", "/b", "/c"]),
                _FakeObs(url="https://target/login", title="Login", forms=[{"action": "/login"}]),
            ],
            current_url="https://target/login",
            authenticated="anonymous",
        )
    )
    out = BrowserVerifier().verify(
        ReplaySpec(
            type="browser",
            payload={
                "url": "https://target/",
                "expect": {
                    "title_contains": "Login",
                    "url_visited": "/login",
                    "link_count_min": 3,
                    "forms_min": 1,
                    "authenticated": "anonymous",
                },
            },
        ),
        _ctx(runtime),
    )
    assert out.validated is True, out.reason
    assert out.signal["link_count"] == 3
    assert out.signal["forms_count"] == 1
    assert runtime.calls and runtime.calls[0]["entry_url"] == "https://target/"


def test_browser_failure_link_count():
    runtime = _FakeRuntime(_FakeResult(observations=[_FakeObs(url="https://target/", links=["/a"])]))
    out = BrowserVerifier().verify(
        ReplaySpec(type="browser", payload={"url": "https://target/", "expect": {"link_count_min": 5}}),
        _ctx(runtime),
    )
    assert out.validated is False
    assert "link_count" in out.reason


def test_browser_blocked_action_match():
    runtime = _FakeRuntime(
        _FakeResult(
            observations=[_FakeObs(url="https://target/")],
            blocked_actions=["sensitive-route:/admin"],
        )
    )
    out = BrowserVerifier().verify(
        ReplaySpec(
            type="browser",
            payload={"url": "https://target/", "expect": {"blocked_action_contains": "/admin"}},
        ),
        _ctx(runtime),
    )
    assert out.validated is True, out.reason


def test_browser_missing_url():
    out = BrowserVerifier().verify(ReplaySpec(type="browser", payload={}), VerifyContext())
    assert out.validated is False
    assert "url missing" in out.reason


def test_browser_runtime_exception_returns_failure():
    runtime = _FakeRuntime(_FakeResult(observations=[]), raise_exc=RuntimeError("playwright unavailable"))
    out = BrowserVerifier().verify(
        ReplaySpec(type="browser", payload={"url": "https://target/"}),
        _ctx(runtime),
    )
    assert out.validated is False
    assert "playwright unavailable" in out.reason


def test_browser_dispatch_via_default_registry():
    runtime = _FakeRuntime(_FakeResult(observations=[_FakeObs(url="https://target/", title="OK")]))
    spec = ReplaySpec(
        type="browser",
        payload={"url": "https://target/", "expect": {"title_contains": "OK"}},
    )
    out = default_registry.dispatch(spec, _ctx(runtime))
    assert out.validated is True, out.reason
