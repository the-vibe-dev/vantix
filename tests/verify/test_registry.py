from __future__ import annotations

import pytest

from secops.verify import (
    ReplaySpec,
    ReplayVerifier,
    VerifierRegistry,
    VerifyContext,
    VerifyOutcome,
    default_registry,
)


class _StubVerifier(ReplayVerifier):
    type = "stub"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        return VerifyOutcome(validated=True, signal={"echo": spec.payload})


def test_default_registry_has_http_and_artifact():
    types = default_registry.types()
    assert "http" in types
    assert "artifact" in types


def test_unknown_type_returns_negative_outcome():
    spec = ReplaySpec(type="does-not-exist", payload={})
    out = default_registry.dispatch(spec, VerifyContext())
    assert out.validated is False
    assert "no verifier registered" in out.reason


def test_register_and_dispatch_custom_verifier():
    registry = VerifierRegistry()
    registry.register(_StubVerifier())
    out = registry.dispatch(ReplaySpec(type="stub", payload={"k": 1}), VerifyContext())
    assert out.validated is True
    assert out.signal == {"echo": {"k": 1}}


def test_register_rejects_blank_type():
    class _Bad(ReplayVerifier):
        type = ""

        def verify(self, spec, ctx):
            return VerifyOutcome(validated=False)

    with pytest.raises(ValueError):
        VerifierRegistry().register(_Bad())


def test_replayspec_from_meta_strips_type():
    spec = ReplaySpec.from_meta({"type": "HTTP", "url": "http://x"})
    assert spec.type == "http"
    assert spec.payload == {"url": "http://x"}
