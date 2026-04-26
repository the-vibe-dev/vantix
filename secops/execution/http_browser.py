from __future__ import annotations

import json
import re
import time
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

from secops.models import Fact, WorkspaceRun


class HttpBrowserMixin:
    """Browser candidate-URL discovery, raw HTTP I/O, browser-vector emission.

    Extracted from ExecutionManager. Pure-function semantics where possible;
    no shared state with peer mixins.
    """

    def _browser_candidate_urls(self, run: WorkspaceRun) -> list[str]:
        config = dict(run.config_json or {})
        browser_cfg = dict(config.get("browser") or {})
        explicit = str(browser_cfg.get("entry_url") or "").strip()
        target = str(run.target or "").strip()
        host = target
        if "://" in host:
            parsed = urlparse(host)
            host = parsed.hostname or host
        if ":" in host and not host.startswith("["):
            host = host.split(":", 1)[0]
        host = host.strip()
        candidates: list[str] = []
        if explicit:
            candidates.append(explicit)
        if host and "://" in target:
            candidates.append(target)
        ports = [str(port).strip() for port in (config.get("ports") or []) if str(port).strip().isdigit()]
        services = [str(item).lower() for item in (config.get("services") or []) if str(item).strip()]
        likely_web_ports = {"80", "443", "3000", "3001", "5000", "5173", "8000", "8080", "8443", "8888"}
        for port in ports:
            if port in likely_web_ports or int(port) >= 1024:
                scheme = "https" if port in {"443", "8443"} else "http"
                if host:
                    candidates.append(f"{scheme}://{host}:{port}")
        if any(token in " ".join(services) for token in ("http", "web", "nginx", "apache", "node", "nessus")) and host:
            if not ports:
                candidates.extend([f"http://{host}", f"http://{host}:3001", f"http://{host}:8080"])
        if host:
            candidates.extend([f"http://{host}", f"http://{host}:3001", f"http://{host}:8080"])
        deduped: list[str] = []
        seen: set[str] = set()
        for item in candidates:
            value = str(item or "").strip()
            if not value:
                continue
            if "://" not in value:
                value = f"http://{value}"
            if value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped

    def _http_request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict | None = None,
        timeout: int = 5,
        headers: dict[str, str] | None = None,
    ) -> dict[str, str | int]:
        body_bytes = None
        request_headers = {"User-Agent": "Vantix-Validation/1.0"}
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update({str(k): str(v) for k, v in headers.items()})
        req = urlrequest.Request(url=url, data=body_bytes, method=method.upper(), headers=request_headers)
        try:
            with urlrequest.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(2_000_000)
                return {
                    "status": int(getattr(resp, "status", 0) or 0),
                    "headers": "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                    "body": raw.decode("utf-8", errors="ignore"),
                }
        except urlerror.HTTPError as exc:
            raw = exc.read(2_000_000) if hasattr(exc, "read") else b""
            return {
                "status": int(exc.code or 0),
                "headers": "\n".join(f"{k}: {v}" for k, v in exc.headers.items()) if exc.headers else "",
                "body": raw.decode("utf-8", errors="ignore"),
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": 0, "headers": "", "body": f"request failed: {exc}"}

    def _http_multipart_request(
        self,
        method: str,
        url: str,
        *,
        field_name: str,
        filename: str,
        content: bytes,
        content_type: str,
        timeout: int = 8,
        headers: dict[str, str] | None = None,
    ) -> dict[str, str | int]:
        boundary = f"----VantixBoundary{int(time.time() * 1000)}"
        payload = b"".join(
            [
                f"--{boundary}\r\n".encode("utf-8"),
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode("utf-8"),
                f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"),
                content,
                b"\r\n",
                f"--{boundary}--\r\n".encode("utf-8"),
            ]
        )
        request_headers = {
            "User-Agent": "Vantix-Validation/1.0",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }
        if headers:
            request_headers.update({str(k): str(v) for k, v in headers.items()})
        req = urlrequest.Request(url=url, data=payload, method=method.upper(), headers=request_headers)
        try:
            with urlrequest.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(30000)
                return {
                    "status": int(getattr(resp, "status", 0) or 0),
                    "headers": "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                    "body": raw.decode("utf-8", errors="ignore"),
                }
        except urlerror.HTTPError as exc:
            raw = exc.read(30000) if hasattr(exc, "read") else b""
            return {
                "status": int(exc.code or 0),
                "headers": "\n".join(f"{k}: {v}" for k, v in exc.headers.items()) if exc.headers else "",
                "body": raw.decode("utf-8", errors="ignore"),
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": 0, "headers": "", "body": f"request failed: {exc}"}

    def _write_http_artifact(
        self,
        out_dir: Path,
        path: str,
        response: dict[str, str | int],
        url: str,
        *,
        request_body: dict | None = None,
    ) -> Path:
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", path).strip("-")[:110] or "http"
        artifact_path = out_dir / f"{slug}.txt"
        body = str(response.get("body") or "")
        headers = str(response.get("headers") or "")
        request_block = ""
        if request_body is not None:
            request_block = f"\nRequest JSON:\n{json.dumps(request_body, indent=2)}\n"
        artifact_path.write_text(
            f"URL: {url}\nStatus: {response.get('status')}\nHeaders:\n{headers[:2000]}\n{request_block}\nBody Snippet:\n{body[:6000]}\n",
            encoding="utf-8",
        )
        return artifact_path

    def _browser_vector(
        self,
        *,
        run_id: str,
        title: str,
        summary: str,
        severity: str,
        evidence: str,
        tags: list[str],
        prerequisites: list[str],
        noise_level: str,
        requires_approval: bool,
        evidence_artifact_ids: list[str] | None = None,
    ) -> Fact:
        score = 0.45
        if severity.lower() in {"high", "critical"}:
            score += 0.2
        if requires_approval:
            score += 0.08
        if noise_level == "quiet":
            score += 0.06
        metadata = {
            "title": title,
            "summary": summary,
            "source": "browser-runtime",
            "severity": severity.lower(),
            "status": "candidate",
            "evidence": evidence,
            "next_action": "review browser evidence and validate safely",
            "noise_level": noise_level,
            "requires_approval": requires_approval,
            "evidence_quality": 0.72,
            "source_credibility": 0.8,
            "novelty": 0.55,
            "noise_level_score": 0.2 if noise_level == "quiet" else 0.7,
            "prerequisites_satisfied": 0.5,
            "prerequisites": prerequisites,
            "score": round(min(0.99, max(0.0, score)), 3),
            "provenance": {"facts": [], "artifacts": [], "origin_phase": "browser-assessment"},
            "scope_check": "required-before-validation",
            "safety_notes": "Bounded validation follows run validation.risk_mode; high-impact vectors are attempted when in scope and recorded with impact metadata.",
            "evidence_artifact_ids": list(evidence_artifact_ids or []),
        }
        return Fact(
            run_id=run_id,
            source="browser-runtime",
            kind="vector",
            value=title,
            confidence=float(metadata["score"]),
            tags=tags,
            metadata_json=metadata,
        )
