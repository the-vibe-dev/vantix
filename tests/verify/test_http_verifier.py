from __future__ import annotations

import http.server
import threading

import pytest

from secops.verify import ReplaySpec, VerifyContext
from secops.verify.http import HttpVerifier


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/ok":
            body = b'{"ok":true,"canary":"yes"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Marker", "vantix-test")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
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


def test_http_happy_path(server):
    out = HttpVerifier().verify(
        ReplaySpec(
            type="http",
            payload={
                "url": f"{server}/ok",
                "expect": {
                    "status": 200,
                    "body_contains": "canary",
                    "header_contains": {"X-Marker": "vantix-test"},
                },
            },
        ),
        VerifyContext(),
    )
    assert out.validated is True, out.reason
    assert out.signal["status"] == 200
    assert out.reproduction_script.startswith("curl ")


def test_http_status_mismatch(server):
    out = HttpVerifier().verify(
        ReplaySpec(type="http", payload={"url": f"{server}/missing", "expect": {"status": 200}}),
        VerifyContext(),
    )
    assert out.validated is False
    assert "Not Found" in out.reason or "status 404" in out.reason


def test_http_missing_url():
    out = HttpVerifier().verify(ReplaySpec(type="http", payload={}), VerifyContext())
    assert out.validated is False
    assert "url missing" in out.reason
