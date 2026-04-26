from __future__ import annotations

import hashlib
import json
import re
import ssl
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from secops.config import settings
from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome


class ScriptVerifier(ReplayVerifier):
    """Static-script / HTML body verifier.

    Replay payload schema:
        url:        str (required)
        method:     str (default GET)
        headers:    dict[str, str]
        insecure:   bool (default False)
        expect:
            status:           int
            contains_any:     list[str]   — at least one substring must appear
            contains_all:     list[str]   — every substring must appear
            pattern_match:    str (regex) — re.search must hit
            app_config_keys:  list[str]   — keys must appear in window.__APP_CONFIG__-style JSON blob
            debug_signal:     bool        — body contains a debug/devtools indicator
    """

    type = "script"

    _APP_CONFIG_RE = re.compile(
        r"(?:window\.__APP_CONFIG__|window\.__CONFIG__|window\.APP_CONFIG)\s*=\s*(\{.*?\})\s*[;<]",
        re.DOTALL,
    )
    _DEBUG_SIGNAL_RE = re.compile(
        r"(sourcemap|sourceMappingURL|webpack://|console\.debug|__REACT_DEVTOOLS|debugger;|/\* debug \*/)",
        re.IGNORECASE,
    )

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        replay = spec.payload
        url = str(replay.get("url") or "").strip()
        if not url:
            return VerifyOutcome(validated=False, reason="replay.url missing")
        method = str(replay.get("method") or "GET").upper()
        headers = {str(k): str(v) for k, v in (replay.get("headers") or {}).items()}
        expect = replay.get("expect") or {}

        req = Request(url, method=method, headers=headers)
        context = ssl.create_default_context()
        if replay.get("insecure"):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        try:
            with urlopen(req, timeout=settings.exploit_validation_http_timeout, context=context) as resp:
                status = resp.status
                raw = resp.read(1024 * 512)
        except URLError as exc:
            return VerifyOutcome(validated=False, reason=f"http error: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            return VerifyOutcome(validated=False, reason=f"http exception: {exc}")

        body = raw.decode("utf-8", errors="replace")
        signal = {
            "status": status,
            "length": len(raw),
            "body_sha256": hashlib.sha256(raw).hexdigest(),
        }
        failed: list[str] = []

        expected_status = expect.get("status")
        if expected_status is not None and int(expected_status) != int(status):
            failed.append(f"status {status} != {expected_status}")

        contains_any = [str(s) for s in (expect.get("contains_any") or [])]
        if contains_any and not any(s in body for s in contains_any):
            failed.append("contains_any not matched")

        contains_all = [str(s) for s in (expect.get("contains_all") or [])]
        missing_all = [s for s in contains_all if s not in body]
        if missing_all:
            failed.append(f"contains_all missing: {missing_all}")

        pattern = expect.get("pattern_match")
        if pattern:
            try:
                if not re.search(str(pattern), body):
                    failed.append("pattern_match did not hit")
            except re.error as exc:
                failed.append(f"pattern_match invalid regex: {exc}")

        cfg_keys = [str(k) for k in (expect.get("app_config_keys") or [])]
        if cfg_keys:
            cfg_match = self._APP_CONFIG_RE.search(body)
            cfg_obj: dict[str, Any] = {}
            if cfg_match:
                try:
                    cfg_obj = json.loads(cfg_match.group(1))
                except (json.JSONDecodeError, ValueError):
                    cfg_obj = {}
            missing_cfg = [k for k in cfg_keys if k not in cfg_obj]
            if missing_cfg:
                failed.append(f"app_config_keys missing: {missing_cfg}")
            else:
                signal["app_config_keys_found"] = cfg_keys

        if expect.get("debug_signal"):
            match = self._DEBUG_SIGNAL_RE.search(body)
            if not match:
                failed.append("debug_signal not detected")
            else:
                signal["debug_signal"] = match.group(1)

        if failed:
            return VerifyOutcome(validated=False, reason="; ".join(failed), signal=signal)

        repro_headers = " ".join(f"-H {k!r}" for k in headers) if headers else ""
        repro = f"curl -sS -X {method} {repro_headers} {url}".strip()
        return VerifyOutcome(validated=True, reproduction_script=repro, signal=signal)
