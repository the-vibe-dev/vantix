"""Pluggable verifier fabric.

Verifiers replay a vector hypothesis against a target and return a
VerifyOutcome. Dispatch is keyed on ``replay.type`` via VerifierRegistry.
"""
from secops.verify.base import ReplayVerifier, ReplaySpec, VerifyContext, VerifyOutcome
from secops.verify.registry import VerifierRegistry, default_registry

__all__ = [
    "ReplaySpec",
    "ReplayVerifier",
    "VerifierRegistry",
    "VerifyContext",
    "VerifyOutcome",
    "default_registry",
]
