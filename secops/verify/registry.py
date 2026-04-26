from __future__ import annotations

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome


class VerifierRegistry:
    """Static registry mapping replay.type → verifier instance."""

    def __init__(self) -> None:
        self._verifiers: dict[str, ReplayVerifier] = {}

    def register(self, verifier: ReplayVerifier) -> None:
        kind = (verifier.type or "").strip().lower()
        if not kind:
            raise ValueError("verifier.type must be a non-empty string")
        self._verifiers[kind] = verifier

    def get(self, kind: str) -> ReplayVerifier | None:
        return self._verifiers.get((kind or "").strip().lower())

    def types(self) -> list[str]:
        return sorted(self._verifiers.keys())

    def dispatch(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        verifier = self.get(spec.type)
        if verifier is None:
            return VerifyOutcome(
                validated=False,
                reason=f"no verifier registered for replay.type={spec.type!r}",
            )
        return verifier.verify(spec, ctx)


def _build_default_registry() -> VerifierRegistry:
    from secops.verify.artifact import ArtifactVerifier
    from secops.verify.browser import BrowserVerifier
    from secops.verify.http import HttpVerifier
    from secops.verify.script import ScriptVerifier

    registry = VerifierRegistry()
    registry.register(HttpVerifier())
    registry.register(ArtifactVerifier())
    registry.register(ScriptVerifier())
    registry.register(BrowserVerifier())
    return registry


default_registry = _build_default_registry()
