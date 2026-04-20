from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if not parsed.scheme:
        raw = f"http://{raw}"
        parsed = urlparse(raw)
    if not parsed.netloc:
        return ""
    return parsed.geturl()


def _same_origin(left: str, right: str) -> bool:
    a = urlparse(left)
    b = urlparse(right)
    return bool(a.scheme and a.netloc and a.scheme == b.scheme and a.netloc == b.netloc)


def _sanitize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        k = str(key or "").strip()
        v = str(value or "")
        if not k:
            continue
        lower = k.lower()
        if lower in {"authorization", "cookie", "set-cookie", "x-api-key"}:
            out[k] = "[REDACTED]"
            continue
        out[k] = v[:400]
    return out


@dataclass(slots=True)
class BrowserPolicy:
    allowed_origins: list[str]
    max_depth: int = 2
    max_pages: int = 25
    max_requests: int = 400
    allow_auth: bool = False
    capture_screenshots: bool = True
    capture_storage: bool = True
    allow_form_submission: bool = False
    allow_sensitive_routes: bool = False
    high_noise: bool = False


@dataclass(slots=True)
class BrowserAuthConfig:
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_selector: str = "input[name='username']"
    password_selector: str = "input[type='password']"
    submit_selector: str = "button[type='submit']"
    steps: list[dict[str, Any]] = field(default_factory=list)
    session_cookies: list[dict[str, Any]] = field(default_factory=list)
    role_label: str = ""


@dataclass(slots=True)
class BrowserObservation:
    url: str
    title: str
    depth: int
    links: list[str]
    forms: list[dict[str, Any]]
    storage_summary: dict[str, Any]
    scripts: list[str]
    dom_summary: dict[str, Any]
    route_hints: list[str]
    js_signals: list[dict[str, Any]]


@dataclass(slots=True)
class BrowserAssessmentResult:
    started_at: str
    completed_at: str
    entry_url: str
    current_url: str
    authenticated: str
    observations: list[BrowserObservation]
    network_summary: dict[str, Any]
    route_graph: list[dict[str, Any]]
    blocked_actions: list[str]
    artifacts: list[dict[str, str]]
    auth_transitions: list[dict[str, Any]]
    dom_diffs: list[dict[str, Any]]
    session_summary: dict[str, Any]


class BrowserRuntimeService:
    def _default_policy(self, run_config: dict[str, Any], entry_url: str) -> BrowserPolicy:
        browser_cfg = dict(run_config.get("browser") or {})
        entry_origin = ""
        if entry_url:
            parsed = urlparse(entry_url)
            if parsed.scheme and parsed.netloc:
                entry_origin = f"{parsed.scheme}://{parsed.netloc}"
        raw_origins = browser_cfg.get("allowed_origins") or ([] if not entry_origin else [entry_origin])
        origins = [str(item).strip() for item in raw_origins if str(item).strip()]
        return BrowserPolicy(
            allowed_origins=origins,
            max_depth=max(0, min(int(browser_cfg.get("max_depth", 2) or 2), 5)),
            max_pages=max(1, min(int(browser_cfg.get("max_pages", 25) or 25), 200)),
            max_requests=max(10, min(int(browser_cfg.get("max_requests", 400) or 400), 5000)),
            allow_auth=bool(browser_cfg.get("allow_auth", False)),
            capture_screenshots=bool(browser_cfg.get("capture_screenshots", True)),
            capture_storage=bool(browser_cfg.get("capture_storage", True)),
            allow_form_submission=bool(browser_cfg.get("allow_form_submission", False)),
            allow_sensitive_routes=bool(browser_cfg.get("allow_sensitive_routes", False)),
            high_noise=bool(browser_cfg.get("high_noise", False)),
        )

    def _auth_config(self, run_config: dict[str, Any]) -> BrowserAuthConfig:
        auth = dict(run_config.get("browser_auth") or {})
        return BrowserAuthConfig(
            login_url=str(auth.get("login_url") or ""),
            username=str(auth.get("username") or ""),
            password=str(auth.get("password") or ""),
            username_selector=str(auth.get("username_selector") or "input[name='username']"),
            password_selector=str(auth.get("password_selector") or "input[type='password']"),
            submit_selector=str(auth.get("submit_selector") or "button[type='submit']"),
            steps=[dict(item) for item in (auth.get("steps") or auth.get("auth_steps") or []) if isinstance(item, dict)],
            session_cookies=[dict(item) for item in (auth.get("session_cookies") or auth.get("cookies") or []) if isinstance(item, dict)],
            role_label=str(auth.get("role_label") or ""),
        )

    def _is_allowed_url(self, url: str, policy: BrowserPolicy) -> bool:
        normalized = _normalize_url(url)
        if not normalized:
            return False
        if not policy.allowed_origins:
            return True
        for origin in policy.allowed_origins:
            parsed = urlparse(origin)
            if not parsed.scheme or not parsed.netloc:
                continue
            allowed = f"{parsed.scheme}://{parsed.netloc}"
            if normalized.startswith(allowed):
                return True
        return False

    def _is_sensitive_route(self, url: str) -> bool:
        lower = (url or "").lower()
        return any(token in lower for token in ("/admin", "/manage", "/settings", "/internal", "/debug", "/private"))

    def _extract_links(self, html: str, current_url: str) -> list[str]:
        links: list[str] = []
        for match in re.findall(r"""href=["']([^"']+)["']""", html or "", flags=re.IGNORECASE):
            joined = urljoin(current_url, match)
            normalized = _normalize_url(joined)
            if normalized:
                links.append(normalized)
        deduped: list[str] = []
        seen: set[str] = set()
        for item in links:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    def _extract_forms(self, html: str) -> list[dict[str, Any]]:
        forms: list[dict[str, Any]] = []
        for idx, chunk in enumerate(re.findall(r"<form[\s\S]*?</form>", html or "", flags=re.IGNORECASE), start=1):
            action_match = re.search(r"""action=["']([^"']*)["']""", chunk, flags=re.IGNORECASE)
            method_match = re.search(r"""method=["']([^"']*)["']""", chunk, flags=re.IGNORECASE)
            fields: list[dict[str, str]] = []
            for input_tag in re.findall(r"<input[\s\S]*?>", chunk, flags=re.IGNORECASE):
                name_match = re.search(r"""name=["']([^"']*)["']""", input_tag, flags=re.IGNORECASE)
                type_match = re.search(r"""type=["']([^"']*)["']""", input_tag, flags=re.IGNORECASE)
                fields.append(
                    {
                        "name": (name_match.group(1) if name_match else "").strip(),
                        "type": (type_match.group(1) if type_match else "text").strip().lower(),
                    }
                )
            forms.append(
                {
                    "id": f"form-{idx}",
                    "action": (action_match.group(1) if action_match else "").strip(),
                    "method": (method_match.group(1) if method_match else "get").strip().lower(),
                    "fields": fields,
                    "auth_like": any(field["type"] == "password" for field in fields),
                }
            )
        return forms

    def _extract_scripts(self, html: str) -> list[str]:
        scripts: list[str] = []
        for match in re.findall(r"""<script[^>]*src=["']([^"']+)["']""", html or "", flags=re.IGNORECASE):
            scripts.append(match.strip())
        return scripts[:50]

    def _extract_js_signals(self, html: str) -> list[dict[str, Any]]:
        body = html or ""
        patterns: list[tuple[str, str]] = [
            ("spa-framework", r"__NEXT_DATA__|__NUXT__|ReactDOM|vue-router|react-router|angular"),
            ("app-config", r"__APP_CONFIG__|__INITIAL_STATE__|window\.config|apiBaseUrl|baseApiUrl"),
            ("graphql-surface", r"/graphql|GraphQL"),
            ("debug-signal", r"debug\s*=\s*true|DEBUG|developer mode|sourceMappingURL"),
            ("feature-flags", r"featureFlag|launchDarkly|growthbook|optimizely"),
        ]
        signals: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for kind, pattern in patterns:
            for match in re.finditer(pattern, body, flags=re.IGNORECASE):
                snippet = body[max(0, match.start() - 24) : min(len(body), match.end() + 48)].strip()
                normalized = re.sub(r"\s+", " ", snippet)[:180]
                key = (kind, normalized.lower())
                if key in seen:
                    continue
                seen.add(key)
                signals.append({"kind": kind, "signal": normalized})
                if len(signals) >= 30:
                    return signals
        return signals

    def _extract_route_hints(self, html: str, current_url: str) -> list[str]:
        hints: list[str] = []
        candidates = re.findall(r"""["']((?:/|https?://)[^"'?#]{1,180})["']""", html or "", flags=re.IGNORECASE)
        for match in candidates:
            normalized = _normalize_url(urljoin(current_url, match))
            if not normalized:
                continue
            lower = normalized.lower()
            if any(token in lower for token in ("/admin", "/debug", "/manage", "/internal", "/graphql", "/swagger", "/openapi")):
                hints.append(normalized)
        deduped: list[str] = []
        seen: set[str] = set()
        for item in hints:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped[:40]

    def _summarize_dom(self, html: str, forms: list[dict[str, Any]], links: list[str]) -> dict[str, Any]:
        password_fields = 0
        hidden_inputs = 0
        for form in forms:
            for field in form.get("fields") or []:
                field_type = str((field or {}).get("type") or "").lower()
                if field_type == "password":
                    password_fields += 1
                if field_type == "hidden":
                    hidden_inputs += 1
        return {
            "link_count": len(links),
            "form_count": len(forms),
            "password_field_count": password_fields,
            "hidden_input_count": hidden_inputs,
            "script_tag_count": len(re.findall(r"<script\b", html or "", flags=re.IGNORECASE)),
        }

    def _collect_storage_summary(self, context: Any, page: Any) -> dict[str, Any]:
        try:
            cookies = context.cookies()
            ls_count = page.evaluate("() => Object.keys(window.localStorage || {}).length")
            ss_count = page.evaluate("() => Object.keys(window.sessionStorage || {}).length")
            return {
                "cookie_count": len(cookies),
                "local_storage_keys": int(ls_count),
                "session_storage_keys": int(ss_count),
                "has_http_only_cookie": any(bool(item.get("httpOnly")) for item in cookies),
                "secure_cookie_count": sum(1 for item in cookies if bool(item.get("secure"))),
            }
        except Exception:  # noqa: BLE001
            return {"error": "storage-inspection-failed"}

    def _page_snapshot(self, *, page: Any, context: Any, html: str, depth: int) -> dict[str, Any]:
        current_url = page.url
        forms = self._extract_forms(html)
        links = self._extract_links(html, current_url)
        scripts = self._extract_scripts(html)
        storage_summary = self._collect_storage_summary(context, page)
        js_signals = self._extract_js_signals(html)
        route_hints = self._extract_route_hints(html, current_url)
        dom_summary = self._summarize_dom(html, forms, links)
        return {
            "url": current_url,
            "title": page.title() or "",
            "depth": depth,
            "forms": forms[:60],
            "links": links[:200],
            "scripts": scripts,
            "storage_summary": storage_summary,
            "js_signals": js_signals,
            "route_hints": route_hints,
            "dom_summary": dom_summary,
        }

    def _dom_diff(self, before: dict[str, Any], after: dict[str, Any], stage: str) -> dict[str, Any]:
        before_dom = dict(before.get("dom_summary") or {})
        after_dom = dict(after.get("dom_summary") or {})
        before_storage = dict(before.get("storage_summary") or {})
        after_storage = dict(after.get("storage_summary") or {})
        return {
            "stage": stage,
            "from_url": str(before.get("url") or ""),
            "to_url": str(after.get("url") or ""),
            "title_changed": str(before.get("title") or "") != str(after.get("title") or ""),
            "navigated": str(before.get("url") or "") != str(after.get("url") or ""),
            "form_delta": int(after_dom.get("form_count") or 0) - int(before_dom.get("form_count") or 0),
            "password_field_delta": int(after_dom.get("password_field_count") or 0) - int(before_dom.get("password_field_count") or 0),
            "link_delta": int(after_dom.get("link_count") or 0) - int(before_dom.get("link_count") or 0),
            "local_storage_delta": int(after_storage.get("local_storage_keys") or 0) - int(before_storage.get("local_storage_keys") or 0),
            "session_storage_delta": int(after_storage.get("session_storage_keys") or 0) - int(before_storage.get("session_storage_keys") or 0),
            "cookie_delta": int(after_storage.get("cookie_count") or 0) - int(before_storage.get("cookie_count") or 0),
            "auth_like_form_removed": int(before_dom.get("password_field_count") or 0) > 0 and int(after_dom.get("password_field_count") or 0) == 0,
        }

    def _resolve_auth_value(self, value: Any, auth_cfg: BrowserAuthConfig) -> str:
        raw = str(value or "")
        return (
            raw.replace("${username}", auth_cfg.username)
            .replace("${password}", auth_cfg.password)
            .replace("${login_url}", auth_cfg.login_url)
        )

    def _normalize_cookie(self, item: dict[str, Any], fallback_url: str) -> dict[str, Any] | None:
        cookie = {key: value for key, value in item.items() if key in {"name", "value", "url", "domain", "path", "httpOnly", "secure", "sameSite", "expires"}}
        if not str(cookie.get("name") or "").strip():
            return None
        if "url" not in cookie and "domain" not in cookie and fallback_url:
            cookie["url"] = fallback_url
        if "path" not in cookie:
            cookie["path"] = "/"
        return cookie

    def assess(self, *, run_id: str, workspace_root: Path, target: str, run_config: dict[str, Any]) -> BrowserAssessmentResult:
        started_at = _utc_now()
        entry_url = _normalize_url((run_config.get("browser") or {}).get("entry_url") or target)
        policy = self._default_policy(run_config, entry_url)
        auth_cfg = self._auth_config(run_config)
        blocked_actions: list[str] = []
        observations: list[BrowserObservation] = []
        route_graph: list[dict[str, Any]] = []
        network_rows: list[dict[str, Any]] = []
        artifacts: list[dict[str, str]] = []
        auth_transitions: list[dict[str, Any]] = []
        dom_diffs: list[dict[str, Any]] = []
        current_url = entry_url
        auth_state = "not_attempted"
        session_summary: dict[str, Any] = {}

        browser_root = workspace_root / "artifacts" / "browser"
        browser_root.mkdir(parents=True, exist_ok=True)

        if not entry_url:
            blocked_actions.append("invalid-entry-url")
            completed_at = _utc_now()
            return BrowserAssessmentResult(
                started_at=started_at,
                completed_at=completed_at,
                entry_url=entry_url,
                current_url=current_url,
                authenticated="failed",
                observations=[],
                network_summary={"total_requests": 0, "by_method": {}, "by_host": {}, "endpoints": []},
                route_graph=[],
                blocked_actions=blocked_actions,
                artifacts=[],
                auth_transitions=[],
                dom_diffs=[],
                session_summary={"run_id": run_id, "authenticated": "failed"},
            )
        if not self._is_allowed_url(entry_url, policy):
            blocked_actions.append("entry-url-not-allowed-by-browser-policy")
            completed_at = _utc_now()
            return BrowserAssessmentResult(
                started_at=started_at,
                completed_at=completed_at,
                entry_url=entry_url,
                current_url=current_url,
                authenticated="failed",
                observations=[],
                network_summary={"total_requests": 0, "by_method": {}, "by_host": {}, "endpoints": []},
                route_graph=[],
                blocked_actions=blocked_actions,
                artifacts=[],
                auth_transitions=[],
                dom_diffs=[],
                session_summary={"run_id": run_id, "authenticated": "failed"},
            )

        try:
            from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
        except Exception:  # noqa: BLE001
            blocked_actions.append("playwright-not-available")
            report = {
                "run_id": run_id,
                "entry_url": entry_url,
                "blocked_actions": blocked_actions,
                "note": "Install playwright and chromium to enable browser assessment.",
                "at": _utc_now(),
            }
            path = browser_root / "browser_runtime_unavailable.json"
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            artifacts.append({"kind": "browser-session-summary", "path": str(path)})
            completed_at = _utc_now()
            return BrowserAssessmentResult(
                started_at=started_at,
                completed_at=completed_at,
                entry_url=entry_url,
                current_url=current_url,
                authenticated="failed",
                observations=[],
                network_summary={"total_requests": 0, "by_method": {}, "by_host": {}, "endpoints": []},
                route_graph=[],
                blocked_actions=blocked_actions,
                artifacts=artifacts,
                auth_transitions=[],
                dom_diffs=[],
                session_summary={"run_id": run_id, "authenticated": "failed", "blocked_actions": blocked_actions},
            )

        with sync_playwright() as p:  # type: ignore[name-defined]
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            requests_seen = 0
            queue: list[tuple[str, int, str]] = [(entry_url, 0, "entry")]
            visited: set[str] = set()
            route_nodes: dict[str, dict[str, Any]] = {}

            def _record_request(req: Any) -> None:
                nonlocal requests_seen
                requests_seen += 1
                if requests_seen > policy.max_requests:
                    return
                parsed = urlparse(req.url)
                network_rows.append(
                    {
                        "url": req.url,
                        "method": req.method,
                        "resource_type": req.resource_type,
                        "host": parsed.netloc,
                        "path": parsed.path or "/",
                        "headers": _sanitize_headers(dict(req.headers)),
                    }
                )

            page.on("request", _record_request)

            if policy.allow_auth and (auth_cfg.login_url or auth_cfg.steps or auth_cfg.session_cookies):
                auth_url = _normalize_url(auth_cfg.login_url or entry_url)
                if auth_url and self._is_allowed_url(auth_url, policy):
                    try:
                        applied_cookies = 0
                        for item in auth_cfg.session_cookies:
                            cookie = self._normalize_cookie(item, auth_url)
                            if cookie is None:
                                continue
                            context.add_cookies([cookie])
                            applied_cookies += 1
                        if applied_cookies:
                            auth_transitions.append(
                                {
                                    "stage": "cookie-import",
                                    "status": "applied",
                                    "cookie_count": applied_cookies,
                                    "role_label": auth_cfg.role_label,
                                }
                            )
                        page.goto(auth_url, wait_until="domcontentloaded", timeout=15000)
                        pre_html = page.content()
                        pre_auth = self._page_snapshot(page=page, context=context, html=pre_html, depth=0)
                        auth_transitions.append(
                            {
                                "stage": "pre-auth",
                                "status": "observed",
                                "url": pre_auth["url"],
                                "title": pre_auth["title"],
                                "storage_summary": pre_auth["storage_summary"],
                            }
                        )
                        if auth_cfg.steps:
                            for step in auth_cfg.steps[:20]:
                                action = str(step.get("action") or "").strip().lower()
                                if action == "goto":
                                    goto_url = _normalize_url(self._resolve_auth_value(step.get("url"), auth_cfg))
                                    if goto_url and self._is_allowed_url(goto_url, policy):
                                        page.goto(goto_url, wait_until="domcontentloaded", timeout=15000)
                                elif action == "fill":
                                    selector = str(step.get("selector") or "").strip()
                                    if selector:
                                        page.fill(selector, self._resolve_auth_value(step.get("value"), auth_cfg))
                                elif action in {"click", "submit", "press"}:
                                    if not policy.allow_form_submission:
                                        blocked_actions.append("auth-submit-blocked-by-policy")
                                        auth_state = "partial"
                                        continue
                                    selector = str(step.get("selector") or "").strip()
                                    if action == "press":
                                        page.press(selector, str(step.get("key") or "Enter"))
                                    elif selector:
                                        page.click(selector)
                                elif action == "wait":
                                    page.wait_for_timeout(max(0, min(int(step.get("ms") or 800), 10000)))
                        elif auth_cfg.username and auth_cfg.password:
                            page.fill(auth_cfg.username_selector, auth_cfg.username)
                            page.fill(auth_cfg.password_selector, auth_cfg.password)
                            if policy.allow_form_submission:
                                page.click(auth_cfg.submit_selector)
                            else:
                                blocked_actions.append("auth-submit-blocked-by-policy")
                                auth_state = "partial"
                        page.wait_for_timeout(1200)
                        post_html = page.content()
                        post_auth = self._page_snapshot(page=page, context=context, html=post_html, depth=0)
                        diff = self._dom_diff(pre_auth, post_auth, "auth-transition")
                        dom_diffs.append(diff)
                        auth_state = auth_state or "not_attempted"
                        if auth_state != "partial":
                            auth_state = (
                                "success"
                                if diff["navigated"] or diff["auth_like_form_removed"] or int(post_auth["storage_summary"].get("cookie_count") or 0) > int(pre_auth["storage_summary"].get("cookie_count") or 0)
                                else "partial"
                            )
                        auth_transitions.append(
                            {
                                "stage": "post-auth",
                                "status": auth_state,
                                "url": post_auth["url"],
                                "title": post_auth["title"],
                                "storage_summary": post_auth["storage_summary"],
                                "dom_diff": diff,
                            }
                        )
                    except Exception as exc:  # noqa: BLE001
                        auth_state = "failed"
                        auth_transitions.append({"stage": "post-auth", "status": "failed", "detail": str(exc)[:200]})
                else:
                    blocked_actions.append("auth-login-url-not-allowed")

            while queue and len(visited) < policy.max_pages:
                url, depth, parent = queue.pop(0)
                normalized = _normalize_url(url)
                if not normalized or normalized in visited:
                    continue
                if depth > policy.max_depth:
                    continue
                if not self._is_allowed_url(normalized, policy):
                    blocked_actions.append(f"blocked-out-of-origin:{normalized}")
                    continue
                if self._is_sensitive_route(normalized) and not policy.allow_sensitive_routes:
                    blocked_actions.append(f"blocked-sensitive-route:{normalized}")
                    continue
                try:
                    page.goto(normalized, wait_until="domcontentloaded", timeout=15000)
                except Exception:  # noqa: BLE001
                    blocked_actions.append(f"navigation-failed:{normalized}")
                    continue
                visited.add(normalized)
                current_url = page.url
                html = page.content()
                snapshot = self._page_snapshot(page=page, context=context, html=html, depth=depth)
                links = list(snapshot["links"])
                forms = list(snapshot["forms"])
                scripts = list(snapshot["scripts"])
                storage_summary = dict(snapshot["storage_summary"]) if policy.capture_storage else {}
                if observations:
                    previous = observations[-1]
                    prior_snapshot = {
                        "url": previous.url,
                        "title": previous.title,
                        "dom_summary": previous.dom_summary,
                        "storage_summary": previous.storage_summary,
                    }
                    dom_diffs.append(self._dom_diff(prior_snapshot, snapshot, "navigation"))
                obs = BrowserObservation(
                    url=current_url,
                    title=str(snapshot["title"] or ""),
                    depth=depth,
                    links=links[:200],
                    forms=forms[:60],
                    storage_summary=storage_summary,
                    scripts=scripts,
                    dom_summary=dict(snapshot["dom_summary"] or {}),
                    route_hints=list(snapshot["route_hints"] or []),
                    js_signals=list(snapshot["js_signals"] or []),
                )
                observations.append(obs)
                route_nodes.setdefault(current_url, {"url": current_url, "depth": depth, "parents": set(), "children": set()})
                if parent != "entry":
                    route_nodes[current_url]["parents"].add(parent)
                for link in links:
                    if _same_origin(current_url, link):
                        route_nodes[current_url]["children"].add(link)
                        if link not in visited and len(queue) < policy.max_pages * 4:
                            queue.append((link, depth + 1, current_url))

                slug = re.sub(r"[^a-zA-Z0-9]+", "-", current_url).strip("-")[:80] or f"page-{len(observations)}"
                dom_path = browser_root / f"{len(observations):03d}_{slug}_dom.json"
                dom_payload = {
                    "url": current_url,
                    "title": obs.title,
                    "depth": depth,
                    "forms": obs.forms,
                    "links": obs.links[:200],
                    "scripts": obs.scripts,
                    "storage_summary": obs.storage_summary,
                    "dom_summary": obs.dom_summary,
                    "route_hints": obs.route_hints,
                    "js_signals": obs.js_signals,
                    "captured_at": _utc_now(),
                }
                dom_path.write_text(json.dumps(dom_payload, indent=2), encoding="utf-8")
                artifacts.append({"kind": "dom-snapshot", "path": str(dom_path)})
                if policy.capture_screenshots:
                    screen_path = browser_root / f"{len(observations):03d}_{slug}.png"
                    try:
                        page.screenshot(path=str(screen_path), full_page=True)
                        artifacts.append({"kind": "screenshot", "path": str(screen_path)})
                    except Exception:  # noqa: BLE001
                        blocked_actions.append(f"screenshot-failed:{current_url}")

            browser.close()

        edges: list[dict[str, str]] = []
        for node in route_nodes.values():
            for child in sorted(node["children"]):
                edges.append({"from": node["url"], "to": child})
        route_graph = edges
        network_by_method: dict[str, int] = {}
        network_by_host: dict[str, int] = {}
        endpoint_counts: dict[str, int] = {}
        for row in network_rows[: policy.max_requests]:
            method = str(row.get("method") or "GET").upper()
            host = str(row.get("host") or "")
            key = f"{method} {row.get('path') or '/'}"
            network_by_method[method] = int(network_by_method.get(method, 0)) + 1
            network_by_host[host] = int(network_by_host.get(host, 0)) + 1
            endpoint_counts[key] = int(endpoint_counts.get(key, 0)) + 1
        endpoints = [{"endpoint": key, "count": count} for key, count in sorted(endpoint_counts.items(), key=lambda item: item[1], reverse=True)[:80]]
        net_summary = {
            "total_requests": len(network_rows),
            "by_method": network_by_method,
            "by_host": network_by_host,
            "endpoints": endpoints,
        }
        route_path = browser_root / "route-discovery.json"
        route_path.write_text(
            json.dumps(
                {
                    "entry_url": entry_url,
                    "visited": [obs.url for obs in observations],
                    "edges": route_graph,
                    "captured_at": _utc_now(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        artifacts.append({"kind": "route-discovery", "path": str(route_path)})
        form_path = browser_root / "form-map.json"
        form_path.write_text(
            json.dumps(
                {
                    "forms": [{"url": obs.url, "forms": obs.forms} for obs in observations],
                    "captured_at": _utc_now(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        artifacts.append({"kind": "form-map", "path": str(form_path)})
        net_path = browser_root / "network-summary.json"
        net_path.write_text(json.dumps(net_summary, indent=2), encoding="utf-8")
        artifacts.append({"kind": "network-summary", "path": str(net_path)})
        auth_state_path = browser_root / "browser-auth-state.json"
        auth_state_path.write_text(
            json.dumps({"auth_transitions": auth_transitions, "dom_diffs": dom_diffs, "captured_at": _utc_now()}, indent=2),
            encoding="utf-8",
        )
        artifacts.append({"kind": "browser-auth-state", "path": str(auth_state_path)})
        signal_path = browser_root / "browser-js-signals.json"
        signal_path.write_text(
            json.dumps(
                {
                    "pages": [
                        {"url": obs.url, "js_signals": obs.js_signals, "route_hints": obs.route_hints, "dom_summary": obs.dom_summary}
                        for obs in observations
                    ],
                    "captured_at": _utc_now(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        artifacts.append({"kind": "browser-js-signals", "path": str(signal_path)})
        sess_path = browser_root / "browser-session-summary.json"
        final_storage = observations[-1].storage_summary if observations else {}
        session_summary = {
            "run_id": run_id,
            "entry_url": entry_url,
            "current_url": current_url,
            "authenticated": auth_state,
            "pages_visited": len(observations),
            "blocked_actions": blocked_actions,
            "auth_transition_count": len(auth_transitions),
            "dom_diff_count": len(dom_diffs),
            "role_label": auth_cfg.role_label,
            "final_storage_summary": final_storage,
            "policy": {
                "allow_auth": policy.allow_auth,
                "allow_form_submission": policy.allow_form_submission,
                "allow_sensitive_routes": policy.allow_sensitive_routes,
                "max_depth": policy.max_depth,
                "max_pages": policy.max_pages,
            },
        }
        sess_payload = {
            **session_summary,
            "captured_at": _utc_now(),
        }
        sess_path.write_text(json.dumps(sess_payload, indent=2), encoding="utf-8")
        artifacts.append({"kind": "browser-session-summary", "path": str(sess_path)})
        completed_at = _utc_now()
        return BrowserAssessmentResult(
            started_at=started_at,
            completed_at=completed_at,
            entry_url=entry_url,
            current_url=current_url,
            authenticated=auth_state,
            observations=observations,
            network_summary=net_summary,
            route_graph=route_graph,
            blocked_actions=blocked_actions,
            artifacts=artifacts,
            auth_transitions=auth_transitions,
            dom_diffs=dom_diffs,
            session_summary=session_summary,
        )
