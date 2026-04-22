#!/usr/bin/env python3
"""P3-7 — Vantix run launcher with first-class ``--quick`` profile.

Wraps ``POST /api/v1/runs`` so operators can launch from the CLI without
touching curl. ``--quick`` flips ``scan_profile`` so the engine takes the
quick-scan path that was previously only reachable by typing the trigger
phrase into the chat flow.

Auth: honors ``VANTIX_BEARER_TOKEN`` if set; otherwise expects a session
cookie jar at ``$VANTIX_COOKIE_JAR`` (Netscape format).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from http.cookiejar import MozillaCookieJar
from urllib.error import HTTPError


def _build_opener() -> urllib.request.OpenerDirector:
    handlers: list = []
    jar_path = os.environ.get("VANTIX_COOKIE_JAR")
    if jar_path:
        jar = MozillaCookieJar(jar_path)
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
            handlers.append(urllib.request.HTTPCookieProcessor(jar))
        except OSError as exc:
            print(f"cookie jar load failed: {exc}", file=sys.stderr)
    return urllib.request.build_opener(*handlers)


def _post(url: str, body: dict) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-CSRF-Token", os.environ.get("VANTIX_CSRF_TOKEN", "vantix-cli"))
    token = os.environ.get("VANTIX_BEARER_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    opener = _build_opener()
    try:
        with opener.open(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"run create failed: HTTP {exc.code}: {detail}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vantix-run", description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("VANTIX_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--target", default="")
    parser.add_argument("--objective", default="")
    parser.add_argument("--tag", action="append", default=[], help="Repeatable.")
    parser.add_argument("--port", action="append", default=[], help="Repeatable.")
    parser.add_argument("--service", action="append", default=[], help="Repeatable.")
    parser.add_argument("--quick", action="store_true", help="Launch with scan_profile=quick.")
    args = parser.parse_args(argv)

    payload = {
        "engagement_id": args.engagement_id,
        "objective": args.objective,
        "target": args.target,
        "services": args.service,
        "ports": args.port,
        "tags": args.tag,
        "config": {},
        "quick": args.quick,
    }
    result = _post(f"{args.base_url.rstrip('/')}/api/v1/runs", payload)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
