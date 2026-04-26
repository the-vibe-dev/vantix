from __future__ import annotations

import hashlib
import json
import ssl
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from secops.config import settings
from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome


class HttpVerifier(ReplayVerifier):
    """HTTP replay verifier ported from ExploitValidationService._replay_http.

    Replay payload schema:
        url:    str (required)
        method: str (default "GET")
        headers: dict[str, str]
        body:    str | dict | None
        insecure: bool (default False) — disables TLS verification
        expect:
            status: int
            body_contains: str
            header_contains: dict[str, str]
    """

    type = "http"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        replay = spec.payload
        url = str(replay.get("url") or "").strip()
        if not url:
            return VerifyOutcome(validated=False, reason="replay.url missing")
        method = str(replay.get("method") or "GET").upper()
        headers = {str(k): str(v) for k, v in (replay.get("headers") or {}).items()}
        body = replay.get("body")
        expect = replay.get("expect") or {}

        data = body.encode("utf-8") if isinstance(body, str) else (json.dumps(body).encode("utf-8") if body else None)
        req = Request(url, data=data, method=method, headers=headers)
        context = ssl.create_default_context()
        if replay.get("insecure"):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        try:
            with urlopen(req, timeout=settings.exploit_validation_http_timeout, context=context) as resp:
                status = resp.status
                resp_headers = {k: v for k, v in resp.getheaders()}
                raw = resp.read(1024 * 256)
        except URLError as exc:
            return VerifyOutcome(validated=False, reason=f"http error: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            return VerifyOutcome(validated=False, reason=f"http exception: {exc}")

        body_text = raw.decode("utf-8", errors="replace")
        signal = {
            "status": status,
            "body_sha256": hashlib.sha256(raw).hexdigest(),
            "length": len(raw),
        }
        failed: list[str] = []
        expected_status = expect.get("status")
        if expected_status is not None and int(expected_status) != int(status):
            failed.append(f"status {status} != {expected_status}")
        expected_substring = expect.get("body_contains")
        if expected_substring and str(expected_substring) not in body_text:
            failed.append("body_contains not matched")
        for h_name, h_sub in (expect.get("header_contains") or {}).items():
            if str(h_sub) not in resp_headers.get(str(h_name), ""):
                failed.append(f"header {h_name} missing expected substring")

        if failed:
            return VerifyOutcome(validated=False, reason="; ".join(failed), signal=signal)

        return VerifyOutcome(
            validated=True,
            reproduction_script=_curl_repro(method, url, headers, body),
            signal=signal,
        )


def _curl_repro(method: str, url: str, headers: dict[str, str], body: Any) -> str:
    parts = ["curl", "-sS", "-X", method]
    for k, v in headers.items():
        parts += ["-H", f"{k}: {v}"]
    if body is not None:
        data = body if isinstance(body, str) else json.dumps(body)
        parts += ["--data", data]
    parts.append(url)
    return " ".join(parts)
