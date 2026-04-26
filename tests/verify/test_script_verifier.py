from __future__ import annotations

import http.server
import threading

import pytest

from secops.verify import ReplaySpec, VerifyContext, default_registry
from secops.verify.script import ScriptVerifier


_BODY_OK = b"""<!doctype html>
<html><head><title>app</title></head>
<body><script>
window.__APP_CONFIG__ = {"apiUrl":"/api","featureFlags":{"x":true},"build":"abc"};
console.debug('boot');
//# sourceMappingURL=app.js.map
</script></body></html>
"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/app":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(_BODY_OK)))
            self.end_headers()
            self.wfile.write(_BODY_OK)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_):
        return


@pytest.fixture
def server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()


def test_script_happy_path_app_config_and_debug(server):
    out = ScriptVerifier().verify(
        ReplaySpec(
            type="script",
            payload={
                "url": f"{server}/app",
                "expect": {
                    "status": 200,
                    "contains_any": ["__APP_CONFIG__"],
                    "app_config_keys": ["apiUrl", "featureFlags"],
                    "debug_signal": True,
                },
            },
        ),
        VerifyContext(),
    )
    assert out.validated is True, out.reason
    assert out.signal["status"] == 200
    assert "apiUrl" in out.signal["app_config_keys_found"]


def test_script_missing_app_config_key(server):
    out = ScriptVerifier().verify(
        ReplaySpec(
            type="script",
            payload={
                "url": f"{server}/app",
                "expect": {"app_config_keys": ["secretKey"]},
            },
        ),
        VerifyContext(),
    )
    assert out.validated is False
    assert "secretKey" in out.reason


def test_script_pattern_match(server):
    out = ScriptVerifier().verify(
        ReplaySpec(
            type="script",
            payload={"url": f"{server}/app", "expect": {"pattern_match": r"build\":\"[a-z]+"}},
        ),
        VerifyContext(),
    )
    assert out.validated is True, out.reason


def test_script_dispatch_via_default_registry(server):
    spec = ReplaySpec(type="script", payload={"url": f"{server}/app", "expect": {"contains_any": ["app"]}})
    out = default_registry.dispatch(spec, VerifyContext())
    assert out.validated is True, out.reason


def test_script_missing_url():
    out = ScriptVerifier().verify(ReplaySpec(type="script", payload={}), VerifyContext())
    assert out.validated is False
    assert "url missing" in out.reason
