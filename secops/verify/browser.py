from __future__ import annotations

from typing import Any

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome


class BrowserVerifier(ReplayVerifier):
    """Thin adapter that drives BrowserRuntimeService.assess() and asserts on the result.

    Replay payload schema:
        url:        str (required) — entry URL
        run_config: dict (optional) — passed through to BrowserRuntimeService.assess
        expect:
            title_contains:           str
            url_visited:              str        — substring of any observation.url
            link_count_min:           int
            blocked_action_contains:  str        — substring of any blocked-action label
            forms_min:                int
            authenticated:            str        — equals BrowserAssessmentResult.authenticated

    The verifier resolves the runtime via:
        1. ctx.extras["browser_runtime"] (used in tests)
        2. otherwise instantiates secops.services.browser_runtime.BrowserRuntimeService
    """

    type = "browser"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        replay = spec.payload
        url = str(replay.get("url") or "").strip()
        if not url:
            return VerifyOutcome(validated=False, reason="replay.url missing")
        expect = replay.get("expect") or {}
        run_config = dict(replay.get("run_config") or {})

        runtime = (ctx.extras or {}).get("browser_runtime")
        if runtime is None:
            from secops.services.browser_runtime import BrowserRuntimeService

            runtime = BrowserRuntimeService()

        try:
            result = runtime.assess(entry_url=url, run_config=run_config, workspace_root=ctx.workspace_root)
        except TypeError:
            try:
                result = runtime.assess(url, run_config)
            except Exception as exc:  # noqa: BLE001
                return VerifyOutcome(validated=False, reason=f"browser assess failed: {exc}")
        except Exception as exc:  # noqa: BLE001
            return VerifyOutcome(validated=False, reason=f"browser assess failed: {exc}")

        observations = list(getattr(result, "observations", []) or [])
        blocked = list(getattr(result, "blocked_actions", []) or [])
        signal: dict[str, Any] = {
            "observations": len(observations),
            "blocked_actions": len(blocked),
            "current_url": getattr(result, "current_url", ""),
            "authenticated": getattr(result, "authenticated", ""),
        }

        failed: list[str] = []

        title_sub = expect.get("title_contains")
        if title_sub:
            joined_titles = " ".join(getattr(obs, "title", "") for obs in observations)
            if str(title_sub) not in joined_titles:
                failed.append("title_contains not matched")

        url_sub = expect.get("url_visited")
        if url_sub:
            if not any(str(url_sub) in getattr(obs, "url", "") for obs in observations):
                failed.append("url_visited not matched")

        link_min = expect.get("link_count_min")
        if link_min is not None:
            total_links = sum(len(getattr(obs, "links", []) or []) for obs in observations)
            if total_links < int(link_min):
                failed.append(f"link_count {total_links} < {link_min}")
            signal["link_count"] = total_links

        forms_min = expect.get("forms_min")
        if forms_min is not None:
            total_forms = sum(len(getattr(obs, "forms", []) or []) for obs in observations)
            if total_forms < int(forms_min):
                failed.append(f"forms_count {total_forms} < {forms_min}")
            signal["forms_count"] = total_forms

        blocked_sub = expect.get("blocked_action_contains")
        if blocked_sub:
            if not any(str(blocked_sub) in str(item) for item in blocked):
                failed.append("blocked_action_contains not matched")

        expected_auth = expect.get("authenticated")
        if expected_auth is not None and str(expected_auth) != str(getattr(result, "authenticated", "")):
            failed.append(f"authenticated {getattr(result, 'authenticated', '')!r} != {expected_auth!r}")

        if failed:
            return VerifyOutcome(validated=False, reason="; ".join(failed), signal=signal)

        return VerifyOutcome(
            validated=True,
            reproduction_script=f"vantix-browser assess {url}",
            signal=signal,
        )
